rule _013cefb6299d98a05613896a42fbaf73826149faa8e4f65ab2199598367dd04_162 {
  meta:
    description = "datamaliciousorder - from files 013cefb6299d98a05613896a42fbaf73826149faa8e4f65ab2199598367dd04c.js, 0c06dd8b12bfc3e2c1af850996d6d8491521ff7d388b68f5777ba0331fdc019f.js, 132ff1453a7923af04a20f49dd066ca04bb88ebe7afde401a6c2fc65c7914aa3.js, 171ae956eec77cd756e9590c111cfd4497c092bee2243cc4440a7d83c5681d41.js, 2b7893a6b737ac548b81d10df994021fb1d845b3f35d65abfe755caf3456dd0e.js, 2fdedcefb80189afd06a39908f42bdaabd099f57148592551b2d85e308c97208.js, 3fd818d5793f57dd75ccd4a27862a26ee7b7b56e6cb64e2d82525d92a3634810.js, 7e1794fbb7e0a4ef856b9aac21a05b42023b74ee5f8284943efdbcf413de45af.js, b25206b63c9bee36248ccd0c338547ad507f372852bc22e8addc0e10b61c2968.js, b5f61b5a99fe3b255cd6c1e4735acde8e360f90a2920554b89657ee70dd40f0f.js, c952e2f0cf45caf1f84bf6cdf29764bb934c8301a1bf9ee5cd48a4963f7921df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "013cefb6299d98a05613896a42fbaf73826149faa8e4f65ab2199598367dd04c"
    hash2       = "0c06dd8b12bfc3e2c1af850996d6d8491521ff7d388b68f5777ba0331fdc019f"
    hash3       = "132ff1453a7923af04a20f49dd066ca04bb88ebe7afde401a6c2fc65c7914aa3"
    hash4       = "171ae956eec77cd756e9590c111cfd4497c092bee2243cc4440a7d83c5681d41"
    hash5       = "2b7893a6b737ac548b81d10df994021fb1d845b3f35d65abfe755caf3456dd0e"
    hash6       = "2fdedcefb80189afd06a39908f42bdaabd099f57148592551b2d85e308c97208"
    hash7       = "3fd818d5793f57dd75ccd4a27862a26ee7b7b56e6cb64e2d82525d92a3634810"
    hash8       = "7e1794fbb7e0a4ef856b9aac21a05b42023b74ee5f8284943efdbcf413de45af"
    hash9       = "b25206b63c9bee36248ccd0c338547ad507f372852bc22e8addc0e10b61c2968"
    hash10      = "b5f61b5a99fe3b255cd6c1e4735acde8e360f90a2920554b89657ee70dd40f0f"
    hash11      = "c952e2f0cf45caf1f84bf6cdf29764bb934c8301a1bf9ee5cd48a4963f7921df"

  strings:
    $x1  = "\"                                                <!-- this script is provided by https://www.javascriptfreecode.com coded by: K" ascii
    $x2  = "\"<a target='_blank' href='https://www.javascriptfreecode.com' style='font-size: 8pt; text-decoration: none'>JavaScript Best Cod" ascii
    $x3  = "\"                                                <!-- this script is provided by https://www.javascriptfreecode.com coded by: K" ascii
    $x4  = "\"</html><a target='_blank' href='https://www.javascriptfreecode.com' style='font-size: 8pt; text-decoration: none'>JavaScript B" ascii
    $x5  = "\"</script><a target='_blank' href='https://www.javascriptfreecode.com' style='font-size: 8pt; text-decoration: none'>JavaScript" ascii
    $s6  = "\"<a target='_blank' href='https://www.javascriptfreecode.com' style='font-size: 8pt; text-decoration: none'>JavaScript Best Cod" ascii
    $s7  = "\"</script><a target='_blank' href='https://www.javascriptfreecode.com' style='font-size: 8pt; text-decoration: none'>JavaScript" ascii
    $s8  = "\"</html><a target='_blank' href='https://www.javascriptfreecode.com' style='font-size: 8pt; text-decoration: none'>JavaScript B" ascii
    $s9  = "  document.write('<a href=\\\"http://www.YourWebSiteHere.com\\\">Drag this link onto your Home button to make this your Home Pag" ascii
    $s10 = "// Be sure to change the \\\"http://www.YourWebSiteHere.com\\\\\\\"\\r\\n\" +" fullword ascii
    $s11 = "\"<!-- font library -->\\r\\n\" +" fullword ascii
    $s12 = "  document.write('<a href=\\\"http://www.YourWebSiteHere.com\\\">Drag this link onto your Home button to make this your Home Pag" ascii
    $s13 = "sorigin><link href=\\\"https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap\\\" rel=\\\"stylesheet\\\">\\r" ascii
    $s14 = "\"<link rel=\\\"stylesheet\\\" href=\\\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.css\\\" integ" ascii
    $s15 = "\"<link rel=\\\"preconnect\\\" href=\\\"https://fonts.googleapis.com\\\"><link rel=\\\"preconnect\\\" href=\\\"https://fonts.gst" ascii
    $s16 = "\"<link rel=\\\"preconnect\\\" href=\\\"https://fonts.googleapis.com\\\"><link rel=\\\"preconnect\\\" href=\\\"https://fonts.gst" ascii
    $s17 = "\"<!-- font awesome library include 4.7 -->\\r\\n\" +" fullword ascii
    $s18 = "\"<link rel=\\\"stylesheet\\\" href=\\\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.css\\\" integ" ascii
    $s19 = "\"<script src=\\\"https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js\\\"></script>\\r\\n\" +" fullword ascii
    $s20 = "\"/* dark-mode theme */\\r\\n\" +" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (1 of ($x*) and 4 of them)
    ) or (all of them)
}