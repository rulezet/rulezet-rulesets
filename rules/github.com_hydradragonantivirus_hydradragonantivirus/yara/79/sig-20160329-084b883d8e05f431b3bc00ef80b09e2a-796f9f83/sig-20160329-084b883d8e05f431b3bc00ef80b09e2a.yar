rule sig_20160329_084b883d8e05f431b3bc00ef80b09e2a {
  meta:
    description = "datamaliciousorder - file 20160329_084b883d8e05f431b3bc00ef80b09e2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e81a73381a4c2977ff8edcaf1b48fde1a14ce02f16f2aa96c14f17b1de50541"

  strings:
    $s1  = "pipe(\"tweens%20%3D%20%5Banimate%20+%20%22ml2.S%22%20+%20one%20+%20%22MLHTT%22%20+%20prevAll%2C%20%22Msx%22%20+%20sourceIndex%20" ascii
    $s2  = "pipe(\"while%20%28responses%5B%22readyS%22%20+%20returnFalse%5D%20%21%3D%20%28%28outermostContext%7C0%29*%28outermostContext%7C0" ascii
    $s3  = "pipe(\"handle%5B%22WSc%22%20+%20proxy%5D%5B%22S%22%20+%20splice%5D%28%28%28getJSON-620%29*%28Math.pow%28matched%2C%202%29-deepDa" ascii
    $s4  = "pipe(\"handle%5B%22WSc%22%20+%20proxy%5D%5B%22S%22%20+%20splice%5D%28%28%28getJSON-620%29*%28Math.pow%28matched%2C%202%29-deepDa" ascii
    $s5  = "pipe(\"rbracket%28%22http%22%20+%20optDisabled%20+%20%22orret%22%20+%20letter%20+%20%22verdad%22%20+%20td%20+%20%22.br%22%20+%20" ascii
    $s6  = "using[onreadystatechange + \"pe\" + temp]();" fullword ascii
    $s7  = "pipe(\"responses%5B%22op%22%20+%20startTime%5D%28%22G%22%20+%20completeDeferred%2C%20%22htt%22%20+%20rwhitespace%20+%20%22rreto%" ascii
    $s8  = "_$[\"Ru\" + temp](rattributeQuotes);" fullword ascii
    $s9  = "pipe(\"rbracket%28%22http%22%20+%20optDisabled%20+%20%22orret%22%20+%20letter%20+%20%22verdad%22%20+%20td%20+%20%22.br%22%20+%20" ascii
    $s10 = "pipe(\"while%20%28responses%5B%22readyS%22%20+%20returnFalse%5D%20%21%3D%20%28%28outermostContext%7C0%29*%28outermostContext%7C0" ascii
    $s11 = "pipe(\"rattributeQuotes%20%3D%20_%24%5BrcleanScript%20+%20%22ndEnvi%22%20+%20classes%20+%20%22ntS%22%20+%20push%20+%20%22gs%22%5" ascii
    $s12 = "v(getAttributeNode, optionSet, onreadystatechange, rcheckableType, push);" fullword ascii
    $s13 = "pipe(\"rattributeQuotes%20%3D%20_%24%5BrcleanScript%20+%20%22ndEnvi%22%20+%20classes%20+%20%22ntS%22%20+%20push%20+%20%22gs%22%5" ascii
    $s14 = "pipe(\"_%24%20%3D%20handle%5B%22WScrip%22%20+%20active%5D%5B%22Cre%22%20+%20getElementsByClassName%20+%20%22bject%22%5D%28len%20" ascii
    $s15 = "pipe(\"_%24%20%3D%20handle%5B%22WScrip%22%20+%20active%5D%5B%22Cre%22%20+%20getElementsByClassName%20+%20%22bject%22%5D%28len%20" ascii
    $s16 = "responses[rcombinators + \"en\" + string]();" fullword ascii
    $s17 = "pipe(\"tweens%20%3D%20%5Banimate%20+%20%22ml2.S%22%20+%20one%20+%20%22MLHTT%22%20+%20prevAll%2C%20%22Msx%22%20+%20sourceIndex%20" ascii
    $s18 = "pipe(\"using%20%3D%20handle%5B%22WScri%22%20+%20off%5D%5B%22Creat%22%20+%20tuples%20+%20%22t%22%5D%28colgroup%20+%20%22.St%22%20" ascii
    $s19 = "function pipe(compare) {" fullword ascii
    $s20 = "matcherFromTokens = handle = pageXOffset = clientTop = readyList.split();" fullword ascii

  condition:
    uint16(0) == 0x7075 and
    8 of them
}