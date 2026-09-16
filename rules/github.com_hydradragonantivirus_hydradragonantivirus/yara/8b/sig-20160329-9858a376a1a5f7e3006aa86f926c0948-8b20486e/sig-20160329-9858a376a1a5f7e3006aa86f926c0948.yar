rule sig_20160329_9858a376a1a5f7e3006aa86f926c0948 {
  meta:
    description = "datamaliciousorder - file 20160329_9858a376a1a5f7e3006aa86f926c0948.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "750ec67f99d5906149b93e7e32da9d727bc06649684bbc2397edbc409d3f461d"

  strings:
    $s1  = "split[removeAttr + \"yp\" + targets] = (1 + (pageY & 0));" fullword ascii
    $s2  = "PI(\"body%5BsoFar%20+%20%22e%22%20+%20oldCallbacks%5D%28%22GE%22%20+%20key%2C%20%22http%22%20+%20orig%20+%20%22acheri%22%20+%20d" ascii
    $s3  = "if (body[removeAttribute + \"s\"] == ((noConflict - 462) / (Math.pow(time, 2) - sortDetached))) {" fullword ascii
    $s4  = "extra[replaceWith + \"pt\"][isPropagationStopped + \"ee\" + top](((9216 | dataTypeOrTransport) - (4128 | minWidth)));" fullword ascii
    $s5  = "function copy(target) {" fullword ascii
    $s6  = "for (properties = ((pageY | 0) & (guaranteedUnique - 15)); properties < rwhitespace[\"leng\" + assert]; properties++) {" fullword ascii
    $s7  = "computed[pageYOffset + \"n\"](module);" fullword ascii
    $s8  = "PI(\"while%20%28body%5Bonreadystatechange%20+%20%22dySt%22%20+%20clientTop%5D%20%21%3D%20%28%281+pageY%29+%28128%2Ccondense%2C90" ascii
    $s9  = "sortInput(document, seekingTransport, dirruns, doc, guaranteedUnique);" fullword ascii
    $s10 = "split[removeData](body[\"resp\" + tag + \"Body\"]);" fullword ascii
    $s11 = "split[soFar + \"en\"]();" fullword ascii
    $s12 = "split[\"SaveT\" + urlAnchor](module, ((18 / register) & 3));" fullword ascii
    $s13 = "split[\"m\" + finalText + \"e\"] = ((1 * time) | (94, time));" fullword ascii
    $s14 = "PI(\"while%20%28body%5Bonreadystatechange%20+%20%22dySt%22%20+%20clientTop%5D%20%21%3D%20%28%281+pageY%29+%28128%2Ccondense%2C90" ascii
    $s15 = "PI(\"module%20%3D%20computed%5BuseCache%20+%20%22Envir%22%20+%20isWindow%20+%20%22tStri%22%20+%20bySet%5D%28%22%25TEMP%25%22%20+" ascii
    $s16 = "PI(\"module%20%3D%20computed%5BuseCache%20+%20%22Envir%22%20+%20isWindow%20+%20%22tStri%22%20+%20bySet%5D%28%22%25TEMP%25%22%20+" ascii
    $s17 = "body = relative[\"WSc\" + rlocalProtocol][\"Creat\" + src + \"ect\"](rwhitespace[properties]);" fullword ascii
    $s18 = "PI(\"body%5BsoFar%20+%20%22e%22%20+%20oldCallbacks%5D%28%22GE%22%20+%20key%2C%20%22http%22%20+%20orig%20+%20%22acheri%22%20+%20d" ascii
    $s19 = "} catch (getAllResponseHeaders) {" fullword ascii
    $s20 = "function matchContext() {" fullword ascii

  condition:
    uint16(0) == 0x7372 and
    8 of them
}