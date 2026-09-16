rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_17_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_17_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c1f88366a1156096602109e13d12210b4ec57eaee9acf8a0c52ecee82b5e1b4"

  strings:
    $s1  = "EWSIntf::get_wifi_scan_results: Attempting to lookup GetWifiScanResults with no DLL handle" fullword ascii
    $s2  = "--C-- Setting Sreen-Scraped Creds to WifiDataEntry dialog --C--" fullword wide
    $s3  = "--C-- Resetting previous Creds to WifiDataEntry dialog --C--" fullword wide
    $s4  = "--C-- Setting manually created Creds to WifiDataEntry dialog --C--" fullword wide
    $s5  = "EWSIntf::get_network_info: Attempting to lookup GetNetworkInfo with no DLL handle" fullword ascii
    $s6  = "EWSIntf::get_page: Attempting to lookup GetPage with no DLL handle" fullword ascii
    $s7  = "EWSIntf::get_printer_info: Attempting to lookup GetPrinterInformationW with no DLL handle" fullword ascii
    $s8  = "EWSIntf::post_page: Attempting to lookup PostPage with no DLL handle" fullword ascii
    $s9  = "EWSIntf::is_scanning: Attempting to lookup IsWifiScanning with no DLL handle" fullword ascii
    $s10 = "EWSIntf::set_credentials: Attempting to lookup SetCredentials with no DLL handle" fullword ascii
    $s11 = "  --- TryConnection Failure Dialog ---" fullword wide
    $s12 = "EWSIntf::is_wps_running: Attempting to lookup IsWpsRunning with no DLL handle" fullword ascii
    $s13 = "EWSIntf::run_WPS: Attempting to lookup RunWPSSSIDW with no DLL handle" fullword ascii
    $s14 = "EWSIntf::run_WPS: Attempting to lookup RunWPS with no DLL handle" fullword ascii
    $s15 = "-----\\/---- Dump Network Info -----\\/----" fullword wide
    $s16 = "-----/\\---- Dump Network Info -----/\\----" fullword wide
    $s17 = "--C-- Credentials retrieved from the dialog --C--" fullword wide
    $s18 = "EWSIntf::get_app_status: Attempting to lookup GetApplicationStatusA with no DLL handle" fullword ascii
    $s19 = "EWSIntf::start_wifi_scan: Attempting to lookup StartWifiScanSSIDW with no DLL handle" fullword ascii
    $s20 = "EWSIntf::start_wifi_scan: Attempting to lookup StartWifiScan with no DLL handle" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}