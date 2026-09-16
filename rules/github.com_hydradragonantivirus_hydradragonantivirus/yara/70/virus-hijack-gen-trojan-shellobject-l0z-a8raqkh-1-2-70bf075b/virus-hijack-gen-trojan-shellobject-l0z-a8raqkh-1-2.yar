rule Virus_Hijack_Gen_Trojan_ShellObject_l0Z_a8rAQKh_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.l0Z@a8rAQKh_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80cd4b49000f7023c2eb60de17e5b3bea3544ec2cb352696ce277d9522e5025a"

  strings:
    $s1  = "CFrequencyScanner(%d)::GetDeviceConfig() - Error(0x%X): Failed to CoCreate ScanDeviceConfig. " fullword wide
    $s2  = "InitDbgFile() - fatal tracing error: GetTempPath() returned 0" fullword ascii
    $s3  = "CFrequencyScanner(%d)::SetScanRange - Error (0x%X). pFrequencyMap->get_FrequencyMapping failed." fullword wide
    $s4  = "CFrequencyScanner(%d)::ConfigureComponentMapping - Cant get pTunerScanConfig interface." fullword wide
    $s5  = "CDigitalRecorder(%d)::ChannelAvailable - Error (0x%X). Failed to get SID_BDA_TransportStreamInfo service." fullword wide
    $s6  = "CDigitalRecorder(%d)::GetEASEventInfo - Error (0x%X). Failed to get SID_BDA_EasMessage service." fullword wide
    $s7  = "CDigitalRecorder(%d)::FireEASMessage - Error (0x%X). Failed to get SID_BDA_EasMessage service." fullword wide
    $s8  = "CDigitalRecorder(%d)::GetUserActivityInterval - tuner does not support user activity service.  Ignore GetUserActivityInterval." fullword wide
    $s9  = "CFrequencyScanner(%d)::StartRecorderForScanning - Error. Could get ITuneRequest interface." fullword wide
    $s10 = "CFrequencyScanner::GetConfiguredRecorderInfo - Error(0x%X): Failed to CoCreateInstance RecorderMgr." fullword wide
    $s11 = "CDigitalRecorder(%d)::GetEASEventInfo - Error (0x%X). Failed to CreateEASTuneRequest(%d,%d,%d,%d)" fullword wide
    $s12 = "CDigitalRecorder(%d)::CheckEntitlementToken - Start. ExpectDialog=%d, Language=%s" fullword wide
    $s13 = "CDigitalRecorder(%d)::GetUserActivityService - Error (0x%X). Can't get a tuner for recorder." fullword wide
    $s14 = "CAnalogRecorder(%d)::TuneToChannel: Could not get IScanningTunerEx, 0x%x" fullword wide
    $s15 = "CRecvrServiceModule::Run - SecurityDescriptor Initialize failed" fullword wide
    $s16 = "CFrequencyScanner(%d)::PulseTimeout - Error(0x%X): Failed to get_SignalStrength. " fullword wide
    $s17 = "CFrequencyScanner(%d)::PulseTimeout - loaderState == LOADER_FINISHED skipping retrieving SignalStrength!" fullword wide
    $s18 = "CFrequencyScanner(%d)::PulseTimeout - Error(0x%X): Failed to set loaderState to LOADER_SIGNAL_NOT_LOCKED. " fullword wide
    $s19 = "CFrequencyScanner(%d)::PulseTimeout - Error(0x%X): Failed to set loaderState to LOADER_SIGNAL_LOCKED." fullword wide
    $s20 = "CFrequencyScanner(%d)::StartRecorderForScanning - Error (0x%X). Recorder can't start recording operation for channel(%d)." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}