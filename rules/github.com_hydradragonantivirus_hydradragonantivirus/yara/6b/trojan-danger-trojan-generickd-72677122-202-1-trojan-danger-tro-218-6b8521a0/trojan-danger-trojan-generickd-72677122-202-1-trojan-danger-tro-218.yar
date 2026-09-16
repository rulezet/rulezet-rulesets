import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72677122_202_1_Trojan_Danger_Tro_218 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72677122_202_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_217_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_220_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33b7f9a485cc7a2c3d98607a525632e1373dfd378fe2fdc5f035d56ed73d5d3a"
    hash2       = "ad2cf691ee21b61ad670c150bbaba9203c02c78da45b0dbeaf9c58e4636331a3"
    hash3       = "a37a31a3ba0f739c5f1896eb3d1304a059996f8330ce3d84c8dc0347981fd9f3"

  strings:
    $s1 = "tionMethod><AnalyzerDATVersion>4965.0</AnalyzerDATVersion></CommonFields><Event><EventID>1027</EventID><Severity>3</Severity><GM" ascii
    $s2 = "/AnalyzerHostName><AnalyzerEngineVersion>6500.9779</AnalyzerEngineVersion><AnalyzerDetectionMethod>On-Access Scan</AnalyzerDetec" ascii
    $s3 = "yzerName>McAfee Endpoint Security</AnalyzerName><AnalyzerVersion>10.7.0.3497</AnalyzerVersion><AnalyzerHostName>DESKTOP-M946CRG<" ascii
    $s4 = "\"McAfee Endpoint Security\" ProductVersion=\"10.7.0.3497\" ProductFamily=\"TVD\"><CommonFields><Analyzer>ENDP_AM_1070</Analyzer" ascii
    $s5 = "2022-10-27T22:41:48Z</DetectedUTC><ThreatActionTaken>IDS_ALERT_ACT_TAK_DEL</ThreatActionTaken><ThreatHandled>True</ThreatHandled" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "84a5c39eb178b6e678403c890a52017c" and (all of them)
    ) or (all of them)
}