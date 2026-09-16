rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_2_2_Virus_Hijac_440 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aqG68Ic_8.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqsS8zj_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "838086ed8b4207c84b7c179a283d8cfe128e7e3c50a0073d96c26764f782742d"
    hash2       = "b35021f76bf0585b970e2be0716dae07652242bae8affb1ee54288b367312a8b"
    hash3       = "25580ea287f391443b3f34e0d22069b5b1739b6312c794f7f97a82c0c4488470"
    hash4       = "4e62e7a3b77d4d0abb803c175f51d1242fda33bfd3308991b9e90391cac1c369"

  strings:
    $s1  = "%S - Failed to localize caption string: %s" fullword wide
    $s2  = "Stash::LoadFile(): Unable to read Rich Game Media header from %s" fullword wide
    $s3  = "Stash::LoadFile(): Unable to read size of buffer[%d] from %s" fullword wide
    $s4  = "Stash::LoadFile(): Unable to read buffer[%d] from %s" fullword wide
    $s5  = "Stash::SaveFile(): Unable to write Rich Game Media header to %s" fullword wide
    $s6  = "Stash::GetBuffer(): Invalid buffer id(%u)" fullword wide
    $s7  = "Stash::LoadFile(): Unable to read buffer count from %s" fullword wide
    $s8  = "Stash::SaveFile(): Buffer[%d] doesn't exist in %s" fullword wide
    $s9  = "Stash::SaveFile(): Unable to write size of buffer[%d] to %s" fullword wide
    $s10 = "Stash::SaveFile(): Unable to write buffer[%d] to %s" fullword wide
    $s11 = "Stash::LoadFile(): Unable to open %s" fullword wide
    $s12 = "Stash::SaveFile(): Missing save filename" fullword wide
    $s13 = "Stash::SaveFile(): Unable to open %s" fullword wide
    $s14 = "Stash::SaveFile(): Unable to write buffer count to %s" fullword wide
    $s15 = "Stash::LoadFile(): Unable to allocate buffer object[%d] for %s" fullword wide
    $s16 = "Stash::LoadFile(): Unable to allocate buffer[%d] for %s" fullword wide
    $s17 = "Stash::SetBuffer(): Unable to allocate buffer object[%u]" fullword wide
    $s18 = "Stash::SetBuffer(): Unable to allocate buffer[%u]" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}