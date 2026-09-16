rule Virus_Autorun_Win32_Neshta_A_10 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e878d043e16fe6aff58721054f7376b34bf7db8582d15a5731ad4d07475f008"

  strings:
    $s1  = "DChange Render Target" fullword wide
    $s2  = "DirectSound Cooperative Level" fullword ascii
    $s3  = "Driver = [ %s ]" fullword ascii
    $s4  = "Already Open(Load)" fullword ascii
    $s5  = "Format = [ %s ]" fullword ascii
    $s6  = "Name = [ %s ]" fullword ascii
    $s7  = "Version = [ %u.%u.%u ]" fullword ascii
    $s8  = "Already Open(Save)" fullword ascii
    $s9  = "Device = [ %s ]" fullword ascii
    $s10 = "Failed Creating DirectSound Primary Buffer!" fullword ascii
    $s11 = "Disenable" fullword ascii
    $s12 = "Don't Get Size" fullword ascii
    $s13 = ".?AV?$CUSHandleManager@VCUSVertexBuffer@@V?$Handle@U_tagUSVertexBuffer@@@@@@" fullword ascii
    $s14 = "Release DirectSound Object" fullword ascii
    $s15 = ".?AV?$CUSSaveHandleManager@VINovelTexture@@V?$Handle@U_tagTextureForNovel@@@@@@" fullword ascii
    $s16 = "Release DirectXGraphics Device" fullword ascii
    $s17 = "WHQL Level = [ " fullword ascii
    $s18 = "Pixel Shader Ver. [ %u.%u ]" fullword ascii
    $s19 = ".?AV?$CUSHandleManager@VINovelTexture@@V?$Handle@U_tagTextureForNovel@@@@@@" fullword ascii
    $s20 = "Width = [ %u ]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}