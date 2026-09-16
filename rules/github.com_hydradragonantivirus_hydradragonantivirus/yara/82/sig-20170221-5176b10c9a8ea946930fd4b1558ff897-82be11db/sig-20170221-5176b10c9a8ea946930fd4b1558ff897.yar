rule sig_20170221_5176b10c9a8ea946930fd4b1558ff897 {
  meta:
    description = "datamaliciousorder - file 20170221_5176b10c9a8ea946930fd4b1558ff897.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af351a4986ad67452073f1a621cab3f8c9e330f191965147b68bda07cb206d4d"

  strings:
    $s1  = "ps() + obejcitj() + oluny() + ovyvw() + kjarhy() + zlixezs() + sari() + ircoti() + zzavfyr() + lzuvufji() + ykqyled() + xewxams(" ascii
    $s2  = "return [\"env:\", new String(\"yma\"), new String(\"y\"), new String(\"thizd\"), new String(\"ru\"), new String(\"tcod\"), new S" ascii
    $s3  = "return [\"env:\", new String(\"yma\"), new String(\"y\"), new String(\"thizd\"), new String(\"ru\"), new String(\"tcod\"), new S" ascii
    $s4  = "agonp[yjdyrleqne]([cxyvnic() + exyjy() + gibho() + utaf() + acjucu() + gcaxi() + yvdoqcuh() + gcegoqki() + cavon() + ibison() + " ascii
    $s5  = "return [new String(\"hs\"), new String(\"h\"), \"cmd.\", new String(\"q\"), new String(\"s\"), new String(\"i\")][2];" fullword ascii
    $s6  = "function ircoti() {" fullword ascii
    $s7  = "return [new String(\"iz\"), \"  -'\", new String(\"ifa\"), new String(\"etke\"), new String(\"scocc\"), new String(\"bfap\"), ne" ascii
    $s8  = "() + obavyz() + kvunfy() + pbavbos() + gxyxxe() + sinegy() + yvyq() + dgyznu() + gapo() + mpusowne() + jixtirz() + kwydpe() + ek" ascii
    $s9  = "return [new String(\"iz\"), \"  -'\", new String(\"ifa\"), new String(\"etke\"), new String(\"scocc\"), new String(\"bfap\"), ne" ascii
    $s10 = "g(\"oxu\"), new String(\"emw\"), \".Net\"][8];" fullword ascii
    $s11 = "var uroxizanw = [new String(\"asa\"), new String(\"qi\"), new String(\"z\"), new String(\"odc\"), new String(\"e\"), typeof XMLH" ascii
    $s12 = "var uroxizanw = [new String(\"asa\"), new String(\"qi\"), new String(\"z\"), new String(\"odc\"), new String(\"e\"), typeof XMLH" ascii
    $s13 = "return [new String(\"aqo\"), new String(\"i\"), new String(\"azj\"), new String(\"y\"), new String(\"uxly\"), new String(\"qum\"" ascii
    $s14 = "return [new String(\"u\"), new String(\"oji\"), new String(\"o\"), new String(\"a\"), \".Web\", new String(\"uki\"), new String(" ascii
    $s15 = "return [new String(\"meg\"), new String(\"naf\"), new String(\"es\"), new String(\"ero\"), new String(\"nxyp\"), new String(\"lc" ascii
    $s16 = "return [new String(\"meg\"), new String(\"naf\"), new String(\"es\"), new String(\"ero\"), new String(\"nxyp\"), new String(\"lc" ascii
    $s17 = "return [new String(\"ra\"), new String(\"dsej\"), new String(\"cbab\"), new String(\"agxu\"), new String(\"s\"), \"i='^\", new S" ascii
    $s18 = "function usup() {" fullword ascii
    $s19 = "function fzursoji() {" fullword ascii
    $s20 = "return [new String(\"i\"), new String(\"oh\"), new String(\"uvy\"), new String(\"ola\"), new String(\"si\"), new String(\"u\"), " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}