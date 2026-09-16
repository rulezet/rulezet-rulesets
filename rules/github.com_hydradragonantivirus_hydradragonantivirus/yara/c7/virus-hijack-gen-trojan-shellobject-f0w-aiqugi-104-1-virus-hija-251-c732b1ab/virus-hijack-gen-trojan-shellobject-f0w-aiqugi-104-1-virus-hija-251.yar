rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_104_1_Virus_Hija_251 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_104_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_105_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_106_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1402d55ebe79764aa6b500d90065bfe6cac3be6e4b121d503aade48ba3beab58"
    hash2       = "b855bce10c0efd4998e88e95f6bfa4a2f6088c7c5b1befadcff2bb2045f159c7"
    hash3       = "7c9e89c6d6226a5bbb0a4027211b230c847f293a3162d91841125bf0ad032ad9"
    hash4       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash5       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"
    hash6       = "b2108dfb3889c739424c76cfab89967b106303bbb48527797663968a5fad0c9c"
    hash7       = "91108d07454bd8e212cc115ef1211832c7fcadce9bb9fbae1000811f0ccaad7b"

  strings:
    $s1  = "<!-- Generator: Adobe Illustrator 15.1.0, SVG Export Plug-In . SVG Version: 6.00 Build 0)  -->" fullword ascii
    $s2  = "}<!DOCTYPE svg  PUBLIC '-//W3C//DTD SVG 1.1//EN'  'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'>" fullword ascii
    $s3  = "<!DOCTYPE svg  PUBLIC '-//W3C//DTD SVG 1.1//EN'  'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'>" fullword ascii
    $s4  = "<circle cx=\"12\" r=\"2\" cy=\"22\"/>" fullword ascii
    $s5  = "<circle cx=\"20\" r=\"2\" cy=\"14\"/>" fullword ascii
    $s6  = "<circle cx=\"20\" r=\"2\" cy=\"22\"/>" fullword ascii
    $s7  = "<circle cx=\"12\" r=\"2\" cy=\"14\"/>" fullword ascii
    $s8  = "-height:normal;font-family:sans-serif;text-indent:0;text-align:start;text-decoration:none;text-decoration-line:none;text-decorat" ascii
    $s9  = "<circle cx=\"16\" r=\"4\" cy=\"12\"/>" fullword ascii
    $s10 = "           rdf:resource=\"http://purl.org/dc/dcmitype/StillImage\" /><dc:title /></cc:Work></rdf:RDF></metadata><defs" fullword ascii
    $s11 = "irection:ltr;baseline-shift:baseline;text-anchor:start;white-space:normal;clip-rule:nonzero;display:inline;overflow:visible;visi" ascii
    $s12 = "<path d=\"m16 0c-8.8 0-16 12-16 12s7.2 12 16 12 16-12 16-12-7-12-16-12zm0 20c-4.4 0-8-3.6-8-8s3.6-8 8-8 8 3.6 8 8-4 8-8 8z\"/>" fullword ascii
    $s13 = "lters:linearRGB;solid-color:#000000;solid-opacity:1;fill:#ffffff;fill-opacity:1;fill-rule:nonzero;stroke:none;stroke-width:10;st" ascii
    $s14 = "ng:0px;word-spacing:0px;fill:#000000;fill-opacity:1;stroke:none;stroke-width:6.24843645\"" fullword ascii
    $s15 = "<path d=\"m32 4h-8c0-2.2-1.8-4-4-4h-8c-2.2 0-4 1.8-4 4h-8v4h4v18c0 3.3 2.7 6 6 6h12c3.3 0 6-2.7 6-6v-18h4v-4zm-8 22c0 1.1-0.9 2-" ascii
    $s16 = "troke-linejoin:miter;stroke-miterlimit:4;stroke-dasharray:none;stroke-dashoffset:0;stroke-opacity:1;color-rendering:auto;image-r" ascii
    $s17 = "<polygon points=\"0 0 24 16 0 32\" fill=\"#4d4d4f\"/>" fullword ascii
    $s18 = "endering:auto;shape-rendering:auto;text-rendering:auto;enable-background:accumulate\" />" fullword ascii
    $s19 = "ion-style:solid;text-decoration-color:#000000;letter-spacing:normal;word-spacing:normal;text-transform:none;writing-mode:lr-tb;d" ascii
    $s20 = "<path d=\"m32 4h-8c0-2.2-1.8-4-4-4h-8c-2.2 0-4 1.8-4 4h-8v4h4v18c0 3.3 2.7 6 6 6h12c3.3 0 6-2.7 6-6v-18h4v-4zm-8 22c0 1.1-0.9 2-" ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}