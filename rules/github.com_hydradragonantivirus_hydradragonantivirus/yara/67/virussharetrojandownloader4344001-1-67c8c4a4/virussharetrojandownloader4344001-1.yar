rule VirusShareTrojanDownLoader4344001_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader4344001_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efda0ea85143b023921fe1b783f9d4a3569f9212e55081fb491e7de521d28578"

  strings:
    $s1  = "LIf the problem still exists after retry, please contact Trend Micro Support.*http://www.trendmicro.com/support/consumer" fullword wide
    $s2  = "Please log into this computer with Administrator privileges before trying again." fullword wide
    $s3  = "downloaded combining Outings spyware 83 " fullword ascii
    $s4  = "grows Execute " fullword ascii
    $s5  = "refining ONTOLOGY tempDB " fullword ascii
    $s6  = "interview unleashing Boundary unprocessed Options " fullword ascii
    $s7  = "Coprocessor Oracle experiences CEATEC " fullword ascii
    $s8  = "Bind Typeahead OpenServer " fullword ascii
    $s9  = "Operation's Backs passing " fullword ascii
    $s10 = "compute jail Logistik " fullword ascii
    $s11 = "encrypted greatly construct " fullword ascii
    $s12 = "Template CBM flexible 2015 controls " fullword ascii
    $s13 = "Marvin SharePoint comment hyperbola " fullword ascii
    $s14 = "encode databaseid mein Script " fullword ascii
    $s15 = "Description starting governors beneficial " fullword ascii
    $s16 = "Authenticode Failure obscene " fullword ascii
    $s17 = "BMP oeuvres Threaded PolicyFailureInfo" fullword ascii
    $s18 = "Win16 sheet grasp Download " fullword ascii
    $s19 = "Hosting ragged create " fullword ascii
    $s20 = "Dialogue ePUB Newer " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}