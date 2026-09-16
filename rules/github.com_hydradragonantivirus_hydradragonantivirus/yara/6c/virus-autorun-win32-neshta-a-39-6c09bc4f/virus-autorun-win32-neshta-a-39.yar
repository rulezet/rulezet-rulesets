rule Virus_Autorun_Win32_Neshta_A_39 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_39.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd1acd8cac6a559fcfa07cea7ef412495b59d98c2802f22c5dbd31e10e67c896"

  strings:
    $s1  = "failed to get process token information" fullword wide
    $s2  = "failed to get process handle" fullword wide
    $s3  = "failed to open process token" fullword wide
    $s4  = "hook.dll loaded  count=%d s->gsSMemAttachCounter=%d " fullword wide
    $s5  = "nView shutdown successful! hook.dll loaded  count=%d s->gsSMemAttachCounter=%d threadHooks=%d sleep count=%d" fullword wide
    $s6  = "NOT all instances of nView released! hook.dll loaded count=%d threadHooks=%d" fullword wide
    $s7  = "explorer.exe shell:Appsfolder\\" fullword wide
    $s8  = "Active user name (%s) != process user name (%s)" fullword wide
    $s9  = "Shared heap mutex(ghSharedMemoryMutex) failed to release!" fullword wide
    $s10 = "Shared heap mutex(ghPseudoMaxWindowDataMutex) failed to release!" fullword wide
    $s11 = "failed to open process handle" fullword wide
    $s12 = "Shared heap mutex(ghPseudoMaxWindowDataMutex) timeout!" fullword wide
    $s13 = "dispID 0x%08x targetId(0x%08x) connected(%i) phyConnected(%i) active(%i) forcedEDID(%i) virtualDisp(%i)  name(%S)" fullword wide
    $s14 = "OletuscNVIDIA RTX Desktop Manager vaatii Microsoft .NET Framework -version 4.5.  Haluatko asentaa sen nyt?tNVIDIA RTX Desktop Ma" wide
    $s15 = "nView WOW Process Shutdown Event" fullword wide
    $s16 = "timeout while waiting for WOW process to idle." fullword wide
    $s17 = "nView Main Process Active" fullword wide
    $s18 = "nView Wathcdog Process Active" fullword wide
    $s19 = "entering watchdog wait state.  nviewProcessHandleCount=%d" fullword wide
    $s20 = "O NVIDIA RTX Desktop Manager requer as bibliotecas de tempo de execu" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}