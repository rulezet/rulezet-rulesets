rule _20160921_016aab466e10a29b831eb85b27664027_20160921_18cdf3dec8ac_4111 {
  meta:
    description = "datamaliciousorder - from files 20160921_016aab466e10a29b831eb85b27664027.js, 20160921_18cdf3dec8ac4b7697e775bc56ddeba9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a541dd7e97eedc43f6bcf89f007176352c81c1d1240a76218e73cf5bb3b171"
    hash2       = "1a1aa090c906360f52952b29d512b8c450c7e8c8cff28bc6fded6af15377b37c"

  strings:
    $s1 = "return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s2 = "),(function f000(){return \"MMz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000(" ascii
    $s3 = " \"DNa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s4 = "tion f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"BQb\";})(),(function f000(){retur" ascii
    $s5 = "\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}