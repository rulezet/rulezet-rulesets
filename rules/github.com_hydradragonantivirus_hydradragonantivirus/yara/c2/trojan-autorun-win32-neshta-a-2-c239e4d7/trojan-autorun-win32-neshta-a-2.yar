rule Trojan_Autorun_Win32_Neshta_A_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Neshta.A_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1180a1adb98a854af7bd5f681cd90e79b9a45db220f74d81778ad31eaa64339"

  strings:
    $x1  = "@@||code.jquery.com^$script,domain=adkami.com|ahvsh.com|animecomplet.com|blablastream.com|blablastream.rip|filelions.com|filelio" ascii
    $s2  = "@@||cloudflare.com/cdn-cgi/scripts/*/cloudflare-static/rocket-loader.min.js$script" fullword ascii
    $s3  = "@@||content.jwplatform.com/libraries/$script,domain=animevostfr.tv|protect-stream.com" fullword ascii
    $s4  = "@@||ssl.p.jwpcdn.com/player/v/$script,stylesheet,xmlhttprequest,domain=ahvsh.com|allviid.live|allviid.xyz|allviids.xyz|cloudemb." ascii
    $s5  = "@@||wp.com/*/build/photon/$script,domain=animevostfr.tv|filmstreaming1vf.co|voircartoon.com" fullword ascii
    $s6  = "@@||wp.com/*/wp-includes/js/$script,domain=animevostfr.tv|filmstreaming1vf.co|voircartoon.com" fullword ascii
    $s7  = "@@||sdk.privacy-center.org^$script,domain=frandroid.com" fullword ascii
    $s8  = "@@||www.mrsexe.com/bower_components/jquery/dist/jquery.min.js$script,domain=mrsexe.com" fullword ascii
    $s9  = "@@||st.chatango.com/js/gz/emb.js$script,domain=adkami.com|crichd.com|crichd.to|crichd.xyz|flystream.fr|gdriveplayer.to|jetanimes" ascii
    $s10 = "@@||mrsexe.com/api/video.6.6.3.min.js$script,domain=mrsexe.com" fullword ascii
    $s11 = "@@||www.mrsexe.com/jwplayer/jwplayer.$script,domain=mrsexe.com" fullword ascii
    $s12 = "@@||www.mrsexe.com/inc/clic.php?video=$script,domain=mrsexe.com" fullword ascii
    $s13 = "@@||suggestqueries.google.com/complete/search?$script,domain=9xbuddy.xyz|offmp3.com" fullword ascii
    $s14 = "@@||youtube.com/iframe_api|$script" fullword ascii
    $s15 = "@@||ssl.p.jwpcdn.com/player/v/$script,stylesheet,xmlhttprequest,domain=ahvsh.com|allviid.live|allviid.xyz|allviids.xyz|cloudemb." ascii
    $s16 = "||productcatalog.channeladvisor.com^$document,removeparam=PCAT_vNextTracking_LocalWidget" fullword ascii
    $s17 = "@@||challenges.cloudflare.com/turnstile/*/api.js?$script" fullword ascii
    $s18 = "@@||film-francais-vf.com/assets/js/jquery-3.2.1.min.js$script,domain=saison-streaming.com" fullword ascii
    $s19 = "@@||st.chatango.com/js/gz/emb.js$script,domain=adkami.com|crichd.com|crichd.to|crichd.xyz|flystream.fr|gdriveplayer.to|jetanimes" ascii
    $s20 = "@@||code.jquery.com^$script,domain=adkami.com|ahvsh.com|animecomplet.com|blablastream.com|blablastream.rip|filelions.com|filelio" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}