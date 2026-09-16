rule _20160323_f40fb2ffed57cd10def05ab35b3bd138_20160324_0e965fcc51ae_4098 {
  meta:
    description = "datamaliciousorder - from files 20160323_f40fb2ffed57cd10def05ab35b3bd138.js, 20160324_0e965fcc51aed855290c7c82a7514dfc.js, 20160324_73a8b488c20f9995b42fed815863b6ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9d249023ae341a7afe7ecbeb22d83c43b5df0f07117fdf26931e6c3ba6d1aae"
    hash2       = "da7fc318f6988532e5e22f4fd4e18744f136aa3fda6cecbc39334c63c2aed2a7"
    hash3       = "46f95ef55c666856d74d41f8daa97676afa807de69c16a6dc908c3ccb6fdafc7"

  strings:
    $s1 = ") { return siblings( elem.firstChild ); }, contents: function( elem ) { return jQuery.nodeName( elem, \\\"iframe\\\" ) ? elem.co" ascii
    $s2 = "tDocument || elem.contentWindow.document : jQuery.merge( [], elem.childNodes ); } }, function( name, fn ) { jQuery.fn[ name ] = " ascii
    $s3 = "function( until, selector ) { var ret = jQuery.map( this, fn, until );\";" fullword ascii
    $s4 = "turn dir( elem, \\\"nextSibling\\\", until ); }, prevUntil: function( elem, i, until ) { return dir( elem, \\\"previousSibling" ascii
    $s5 = "l ); }, siblings: function( elem ) { return siblings( ( elem.parentNode || {} ).firstChild, elem ); }, children: function( elem " ascii

  condition:
    (uint16(0) == 0x4555 and (all of them)
    ) or (all of them)
}