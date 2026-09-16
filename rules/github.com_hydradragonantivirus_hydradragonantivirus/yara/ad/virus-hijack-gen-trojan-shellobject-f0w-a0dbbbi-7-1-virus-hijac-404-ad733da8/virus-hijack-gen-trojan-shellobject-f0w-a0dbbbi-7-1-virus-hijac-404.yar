rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_7_1_Virus_Hijac_404 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_20.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_12.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0255cd2cf4f9600aa284e4fffc627641429d2d38e5fa1ac5b1a34dbc099ad2cc"
    hash2       = "022bc1efd735f0b891ae6eb5df74939e368e6b129e799f53c37d4d63b3a08efb"
    hash3       = "b195194f85cd52d826bc334f0021646b6503a7a26a2d1b58db02f130676aa40e"
    hash4       = "ebf10e649fe855c0c01c95d4e134f4202e53c5f2db2c2eba4e165939a346ea7d"
    hash5       = "97121aeedf128abc5ad8715f79d3696d32348a8c453f7e1415a75f72b756049d"
    hash6       = "f91e29b13b06cd530269c794e52d77cc838fa87a0cd6c6d81cb492f8f246468b"
    hash7       = "5d9804ff2d27070141d1d4026f463726ee4df82e182a45804922613d9e80c7d3"
    hash8       = "19cbcc29628d4c642c52ee515e5c0cadbee9dbc08e29cd2abf9ce25ab121a57b"
    hash9       = "c2816a5380456292f9574b067d7b3197da5210eadcc6b2977fcf8b8eac5fd135"
    hash10      = "293cc6207e0313f3e6e3e9fce113d6f7a2f721942b9fab96da2318d55bc5d66e"

  strings:
    $s1  = "(GMT %c%i; %i.%i.%i at %i:%i:%i); %s@%s; %s; %s %s processor(s); %i MB RAM" fullword ascii
    $s2  = "UNKNOWN COMMAND - \"%s\"" fullword ascii
    $s3  = "Listing of %s:" fullword ascii
    $s4  = "Windows %i.%i build %i" fullword ascii
    $s5  = "stop mic" fullword ascii
    $s6  = "record mic" fullword ascii
    $s7  = "close mic" fullword ascii
    $s8  = "Windows Vista build %i" fullword ascii
    $s9  = "Windows 8 build %i" fullword ascii
    $s10 = "Windows Server 2003 build %i" fullword ascii
    $s11 = "Windows XP build %i" fullword ascii
    $s12 = "Windows 7 build %i" fullword ascii
    $s13 = "Windows 2000 build %i" fullword ascii
    $s14 = "save mic %s" fullword ascii
    $s15 = "open new type waveaudio alias mic buffer 6" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}