rule _20160921_2fddda42e5911e6501568e734d430149_20160921_9d32b55f93b8_4837 {
  meta:
    description = "datamaliciousorder - from files 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js, 20160921_aed247f3d2282ef44bd04021d1a47ef8.js, 20160921_b9bf4d00098353791f6752da8f2fba0d.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash2       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash3       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"
    hash4       = "163159bd2bdf088e94bb401b56d374651d890ca6420982f4654021ab58ff2e2d"
    hash5       = "fb6ed05e313f10d63719b3d6465378a522453c08ee11e88d9852f5e4ba4f69fa"
    hash6       = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"

  strings:
    $s1 = "(),(function f000(){return \"WIj\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(),(function f000" ascii
    $s2 = " \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"Qp\";})(),(funct" ascii
    $s3 = "urn \"RPt\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(" ascii
    $s4 = "Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Rh\";})(),(function " ascii
    $s5 = "eturn \"PLy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}