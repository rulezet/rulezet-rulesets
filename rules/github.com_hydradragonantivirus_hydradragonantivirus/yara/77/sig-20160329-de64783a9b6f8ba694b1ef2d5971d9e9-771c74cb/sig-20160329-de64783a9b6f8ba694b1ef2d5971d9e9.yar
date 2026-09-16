rule sig_20160329_de64783a9b6f8ba694b1ef2d5971d9e9 {
  meta:
    description = "datamaliciousorder - file 20160329_de64783a9b6f8ba694b1ef2d5971d9e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c2e4e26ab968ca6b1af903aa1cad962208e12f0efe2ae38096c086e85660586"

  strings:
    $s1  = "nextUntil[\"op\" + resolveValues](\"GE\" + results, \"http\" + origFn + \"angela\" + adown + \"ardflo\" + each + \"try.\" + retu" ascii
    $s2  = " + uid + \".exe\", !(((155, rfxtypes, 91, add) - (Math.pow(38, what) - 1403)) == rscriptTypeMasked));" fullword ascii
    $s3  = "if (nextUntil[scrollTo + \"s\"] == ((Math.pow(24, what) - 542) * (fadeOut | 5) + (rbrace / 33))) {" fullword ascii
    $s4  = "function addToPrefiltersOrTransports(prevObject, scriptCharset) {" fullword ascii
    $s5  = "source[one + \"ToF\" + overrideMimeType](boolHook, ((statusCode, 248, what) & (81 / status)));" fullword ascii
    $s6  = "source[\"m\" + func + \"de\"] = ((22 | what) - (10 + qsa));" fullword ascii
    $s7  = "expand(\"backgroundClip%20%3D%20%5B%22Msx%22%20+%20ret%20+%20%22.Ser%22%20+%20subordinate%20+%20%22XMLHTT%22%20+%20valueParts%2C" ascii
    $s8  = "nextUntil[\"op\" + resolveValues](\"GE\" + results, \"http\" + origFn + \"angela\" + adown + \"ardflo\" + each + \"try.\" + retu" ascii
    $s9  = "expand(\"attrs%20%3D%20webkitMatchesSelector%5B%22WScr%22%20+%20maxWidth%5D%5B%22Creat%22%20+%20opacity%20+%20%22ct%22%5D%28inte" ascii
    $s10 = "expand(\"rcombinators%5B%22WScri%22%20+%20onabort%5D%5B%22Sle%22%20+%20oldfire%5D%28%28%282%7Cdeep%29*%285-stopped%29*%285%7Cuni" ascii
    $s11 = "function getById() {" fullword ascii
    $s12 = "expand(\"source%5B%22Wr%22%20+%20getAttributeNode%20+%20%22e%22%5D%28nextUntil%5BresolveWith%20+%20%22seBod%22%20+%20specialEasi" ascii
    $s13 = "expand(\"source%5B%22Wr%22%20+%20getAttributeNode%20+%20%22e%22%5D%28nextUntil%5BresolveWith%20+%20%22seBod%22%20+%20specialEasi" ascii
    $s14 = "getById(what, split);" fullword ascii
    $s15 = "expand(\"boolHook%20%3D%20attrs%5B%22Expand%22%20+%20classNames%20+%20%22nment%22%20+%20proxy%20+%20%22ngs%22%5D%28contentDocume" ascii
    $s16 = "source[func + \"p\" + resolveValues]();" fullword ascii
    $s17 = "source[name + \"pe\"] = (1 + deep);" fullword ascii
    $s18 = "expand(\"boolHook%20%3D%20attrs%5B%22Expand%22%20+%20classNames%20+%20%22nment%22%20+%20proxy%20+%20%22ngs%22%5D%28contentDocume" ascii
    $s19 = "expand(\"while%20%28nextUntil%5BisPropagationStopped%20+%20%22yStat%22%20+%20reverse%5D%20%21%3D%20%28Math.pow%28%2833-el%29%2C%" ascii
    $s20 = "expand(\"rcombinators%5B%22WScri%22%20+%20onabort%5D%5B%22Sle%22%20+%20oldfire%5D%28%28%282%7Cdeep%29*%285-stopped%29*%285%7Cuni" ascii

  condition:
    uint16(0) == 0x656b and
    8 of them
}