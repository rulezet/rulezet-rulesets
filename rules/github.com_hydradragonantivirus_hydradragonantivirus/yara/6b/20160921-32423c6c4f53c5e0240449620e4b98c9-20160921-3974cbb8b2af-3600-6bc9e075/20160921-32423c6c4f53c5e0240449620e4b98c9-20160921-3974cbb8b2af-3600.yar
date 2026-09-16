rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_3974cbb8b2af_3600 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_b2867778b87ab68774c77840f21eaed0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash3       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"

  strings:
    $s1 = "urn \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(f" ascii
    $s2 = "n f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"D" ascii
    $s3 = ")(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000()" ascii
    $s4 = "\"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(functi" ascii
    $s5 = "{return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})()" ascii
    $s6 = "(function f000(){return \"Iq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}