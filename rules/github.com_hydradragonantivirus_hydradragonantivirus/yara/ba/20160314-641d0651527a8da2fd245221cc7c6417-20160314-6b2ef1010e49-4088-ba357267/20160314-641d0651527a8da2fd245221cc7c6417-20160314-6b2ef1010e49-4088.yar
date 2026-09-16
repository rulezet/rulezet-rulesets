rule _20160314_641d0651527a8da2fd245221cc7c6417_20160314_6b2ef1010e49_4088 {
  meta:
    description = "datamaliciousorder - from files 20160314_641d0651527a8da2fd245221cc7c6417.js, 20160314_6b2ef1010e49318cd36d2524aaf64cb6.js, 20160314_f35dcda0d53e9e7375ee094e3449be5e.js, 20160314_f72b6c2947e2988bcfeedbccab261505.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e5073ca874d72b9bf13452d6e5901839020faee9677394a1fcde7d34dd615bc"
    hash2       = "8bcfe1da8b42e7c54a13cb2ec8ec2b304f7e5caf8c5b426c983c9807fb67ed63"
    hash3       = "949a00f82de1e838087a77116a46eba132977592b2b13e9b29dde896340a9ad2"
    hash4       = "3d849fa0176c359b82b918732303c9b6c0c537d63b34dad3e6c1c38ad72a52dd"

  strings:
    $s1 = "n elem.nodeValue;  }   Do not include comment or processing instruction nodes\";" fullword ascii
    $s2 = "  Do not traverse comment nodes    ret += getText( node );   }  } else if ( nodeType === 1 || nodeType === 9 || nodeType === 11 " ascii
    $s3 = "extContent === \\\"string\\\" ) {    return elem.textContent;   } else {     Traverse its children    for ( elem = elem.firstChi" ascii
    $s4 = ") {    Use textContent for elements    innerText usage removed for consistency of new lines (jQuery #11153)   if ( typeof elem.t" ascii
    $s5 = "elem; elem = elem.nextSibling ) {     ret += getText( elem );    }   }  } else if ( nodeType === 3 || nodeType === 4 ) {   retur" ascii

  condition:
    ((uint16(0) == 0x6774 or uint16(0) == 0x7968 or uint16(0) == 0x4b6d or uint16(0) == 0x7342) and (all of them)
    ) or (all of them)
}