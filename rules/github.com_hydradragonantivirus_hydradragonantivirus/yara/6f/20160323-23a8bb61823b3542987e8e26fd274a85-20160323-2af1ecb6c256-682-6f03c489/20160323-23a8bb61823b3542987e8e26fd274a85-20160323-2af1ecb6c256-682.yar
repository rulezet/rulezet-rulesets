rule _20160323_23a8bb61823b3542987e8e26fd274a85_20160323_2af1ecb6c256_682 {
  meta:
    description = "datamaliciousorder - from files 20160323_23a8bb61823b3542987e8e26fd274a85.js, 20160323_2af1ecb6c256575000b18e623a97a8bf.js, 20160323_46a84fd0e158caa05babb68a6d7649eb.js, 20160323_6971fe83ee7210b325f66a9464a32151.js, 20160323_734475f5a9d572b35dbe49262287247e.js, 20160323_93c765e856eb93f1ae3d3e5e35c5b2a8.js, 20160323_949a84f8b38aa41b9ac9bd27f609c626.js, 20160323_a237c36a5c9d5a01b0900386120315fc.js, 20160323_c8fd364be59d5d33d25729d94e5ac7b4.js, 20160323_d12b0e4df473ea93a9fe09042074fded.js, 20160323_d875596b827f99af54b9c2b5c4e2b7a7.js, 20160323_e3df6f714d8a646b1f2c93512e2964ec.js, 20160323_f40fb2ffed57cd10def05ab35b3bd138.js, 20160323_f6929160c922fbcc82608480b84dd1ea.js, 20160323_fb2126a9801595404812e8b9c9ac98f8.js, 20160323_fd03b9ead6ae07ff231884cfee11ff23.js, 20160324_0e965fcc51aed855290c7c82a7514dfc.js, 20160324_14178d728b44bd85d21a418eebbe3910.js, 20160324_5394cc30ec31bb5a9836a16b86cd13fc.js, 20160324_73a8b488c20f9995b42fed815863b6ea.js, 20160324_c35c970cd71a498452a33d2947c95a2a.js, 20160324_cba385abcad9e59f91a075a5340297d4.js, 20160324_d37a356748219f60472be1891614ca37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c06aaf8faf43d59ff710554e5b6c8b76d1837c2e1db9e17f45413c8716a888b"
    hash2       = "e1232d6c1f7f717503f5da77b02592ca82aaaa96f1f1a8228a136b26355bd6bc"
    hash3       = "5c2c2e5bf99ec7d409959b8a18811f1998f85a266f8283f61ea26ade2dd0b71a"
    hash4       = "c818fc3b80050400dffcbf39bd7eb16e825197174193880ad537a17864790caf"
    hash5       = "ea22ffa95e7a05556a8944d06bd1122b60041cad6620371c45334887fac392a2"
    hash6       = "725734d7bcc0ebf99ddc287c3c500447dc1044c2a4dd255a75ba9f6b6808b176"
    hash7       = "3ac85cb37f327bf5e643a1594daa88f7cddc75797ca883edc6bcd357afe08389"
    hash8       = "7e6440d443c70168136bb5adbb7808f4d0a74f432750f67f30a40fd6dbf6af32"
    hash9       = "f27c8fd3403da10bc42176fc6de1d98d07fe180e7f61f1cd8c4836c47511d7a4"
    hash10      = "44c9ae78b743e01f05ece8f8b5636a3769bf24d31856f82f980ea5a42c6c28be"
    hash11      = "1ccb7ec993e724e8ddefc4386c6a91de657874fe64be22d7732a366bc3a2b21c"
    hash12      = "b41ca0f06e745aae5049c4a9eea520c962ed670b14ef1c48dc332862772b55a5"
    hash13      = "a9d249023ae341a7afe7ecbeb22d83c43b5df0f07117fdf26931e6c3ba6d1aae"
    hash14      = "3e033d333baf9a571daf9d36a9150333c42ae6fed765d170e3cda08fa7a63cb9"
    hash15      = "69ce5845bd8210f3805ecdc048b301b771845856c65c30c4e59a32137b343fdb"
    hash16      = "aa4f6b40da27a26c43433cc7099b0817a3303edda718c67729c225050806637f"
    hash17      = "da7fc318f6988532e5e22f4fd4e18744f136aa3fda6cecbc39334c63c2aed2a7"
    hash18      = "28b2374c1f3267d1a952ff6845d881acef2f5f3300550d3a1e3681fc065294fb"
    hash19      = "bf5d9f2a5d6c3ff4313aa9d74a005f480bf28ebd75ecb4d79f1ea78d7d0cd478"
    hash20      = "46f95ef55c666856d74d41f8daa97676afa807de69c16a6dc908c3ccb6fdafc7"
    hash21      = "ecebed24720fc4760b49919bd34a887a503eec42295536e272496192bb8fc061"
    hash22      = "ef00a4a2601c8c6f8a166fbe2589cc2cc5f07073f1cca08ad8431b93c4b80bab"
    hash23      = "474ebc307396ac34363bb5e151d1461ade3518c60a1c35892fb621932f07b7b6"

  strings:
    $s1  = "UEwOTPsSSOk = \" Always skip document fragments if ( cur.nodeType < 11 && ( pos ? pos.index( cur ) > -1 :\";" fullword ascii
    $s2  = "EcYFOloHD = \" Don\\\"t pass non-elements to Sizzle cur.nodeType === 1 && jQuery.find.matchesSelector( cur, selectors ) ) ) {\";" ascii
    $s3  = "function screensaver(aristocrat, welter) {" fullword ascii
    $s4  = "qBzvWe = \"} return this.pushStack( matched.length > 1 ? jQuery.uniqueSort( matched ) : matched ); },\";" fullword ascii
    $s5  = "rIcDuIsg = \" matched.push( cur ); break; } } \";" fullword ascii
    $s6  = " 11 ? parent : null; }, parents: function( elem ) { return dir( elem, \\\"parentNode\\\" ); }, parentsUntil: function( elem, i, " ascii
    $s7  = "uwSjgO = \" Determine the position of an element within the matched set of elements index: function( elem ) {\";" fullword ascii
    $s8  = "l ) { return dir( elem, \\\"parentNode\\\", until ); }, next: function( elem ) { return sibling( elem, \\\"nextSibling\\\" ); }," ascii
    $s9  = "var WUHOHMfe = this[amino];" fullword ascii
    $s10 = "amino = BilRTKUok[1+4+1].split(\"condo\").join(\"\");" fullword ascii
    $s11 = "unction( elem ) { return sibling( elem, \\\"previousSibling\\\" ); }, nextAll: function( elem ) { return dir( elem, \\\"nextSibl" ascii
    $s12 = "   SjNTLLsRetc = \" if ( name.slice( -5 ) !== \\\"Until\\\" ) { selector = until; \";" fullword ascii
    $s13 = "        var transmit = xAbMqtec + \"/\" + welter + BilRTKUok[thickI];" fullword ascii
    $s14 = "    XRmeyJGjFR = \"function sibling( cur, dir ) { do { cur = cur[ dir ]; } while ( cur && cur.nodeType !== 1 );\";" fullword ascii
    $s15 = "    LIrRABYrOpz = \"}jQuery.each( { parent: function( elem ) { var parent = elem.parentNode; return parent && parent.nodeType !=" ascii
    $s16 = "} catch (cNINLnxTF) { };" fullword ascii

  condition:
    (uint16(0) == 0x4555 and (8 of them)
    ) or (all of them)
}