rule _Virus_Hijack_Trojan_GenericKDZ_105924_238_1_Virus_Infector_Gen__406 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.GenericKDZ.105924_238_1.vir, Virus.Infector_Gen.Trojan.Malware.Iq3@aunLb5ni_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38d57b02dd6a282748156e58d28a30953228acd71fa035f3b81414ba058074fb"
    hash2       = "2cadcd8b1f8ecdb43bff150c0be42223c5bb3237fe1effbf0527ee84da508720"

  strings:
    $s1  = "Usage: %s /f <function type> /d <charid lexicon file> /i <input file> /m <main lexicon file> /o <out domain lexicon file> [/l <l" wide
    $s2  = "      /i  <input file>      : domain configuration file" fullword wide
    $s3  = "element[%d].wszReading = %s " fullword wide
    $s4  = "Error when adding word in file %s ( line NO. %d)" fullword wide
    $s5  = "%s. File name: %s, Line %d" fullword wide
    $s6  = " error when adding this word" fullword wide
    $s7  = "Fatal Error: cannot get DU DIC path." fullword wide
    $s8  = "Fatal Error: cannot get builtin DIC path." fullword wide
    $s9  = "      /o  <out domain lexicon file>        : output domain lexicon file" fullword wide
    $s10 = "      /m  <main lexicon file>              : input main lexicon file" fullword wide
    $s11 = "      /d  <charid lexicon file>            : input charid lexicon file" fullword wide
    $s12 = "      /f <function type>    " fullword wide
    $s13 = "element[%d].tone = %d " fullword wide
    $s14 = "element[%d].wCharTC = 0x%x " fullword wide
    $s15 = "element[%d].wCharSC = 0x%x " fullword wide
    $s16 = "File name = %s " fullword wide
    $s17 = " No corresponding charid found, maybe error in Pinyin, tone, or invalid character" fullword wide
    $s18 = "Invalid argument %s!" fullword wide
    $s19 = "Fatal Error: No word has been added." fullword wide
    $s20 = "Sorry, failed to build domain lexicon file!" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}