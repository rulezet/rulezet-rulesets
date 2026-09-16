rule sig_73601337 {
  meta:
    description = "case109 - file 73601337.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-05-29"
    hash1       = "742a8ec0f6aa3812035005e46d8badcaa2dda73865003bf5a2436770b7f9d134"

  strings:
    $s1  = "$deface_url = 'http://pastebin.com/raw.php?i=FHfxsFGT';  //deface url here(pastebin)." fullword ascii
    $s2  = "Edit Shell according to your choice." fullword ascii
    $s3  = "Domain read bypass." fullword ascii
    $s4  = "$auth_pass = \"1337\";                                  //Your Password." fullword ascii
    $s5  = "//Change Shell Theme here//" fullword ascii
    $s6  = "ZhbHVlKTtyZXR1cm4gZmFsc2U7XCc+PGlucHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4iPjwvZm9ybT48YnI+PHNwYW" ascii
    $s7  = "c+PGlucHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4iPjwvZm9ybT48YnI+PHNwYW4+R2xvYiAobGlzdCBkaXIpPC9zcG" ascii
    $s8  = "xudWxsLCI2Iix0aGlzLnBhcmFtLnZhbHVlKTtyZXR1cm4gZmFsc2U7XCc+PGlucHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT" ascii
    $s9  = "#-------------------------------------------------------------------------------" fullword ascii
    $s10 = "onJykuIj4gc2VuZCB1c2luZyBBSkFYPGJyPjx0ZXh0YXJlYSBuYW1lPSdpbnB1dCcgc3R5bGU9J21hcmdpbi10b3A6NXB4JyBjbGFzcz1iaWdhcmVhPiIuaHRtbHNwZW" ascii
    $s11 = "NvcnMtNHUuY29tL2N1cnNvci8yMDEyLzAyLzExL2Nocm9tZS1wb2ludGVyLmh0bWwiIHRhcmdldD0iX2JsYW5rIiB0aXRsZT0iQ2hyb21lIFBvaW50ZXIiPjxpbWcgc3" ascii
    $s12 = "AuYmlnYXJlYSAgICB7IHdpZHRoOjEwMCU7aGVpZ2h0OjI1MHB4O21hcmdpbi10b3A6MHB4OyBib3JkZXItcmFkaXVzOjEwcHg7IGJvcmRlci1jb2xvcjonLiRUaGVtZS" ascii
    $s13 = "d3LmN1cnNvcnMtNHUuY29tL2N1cnNvci8yMDEyLzAyLzExL2Nocm9tZS1wb2ludGVyLmh0bWwiIHRhcmdldD0iX2JsYW5rIiB0aXRsZT0iQ2hyb21lIFBvaW50ZXIiPj" ascii
    $s14 = "dsemRHVnVJSEJ2Y25SY2JpSTdEUXAzYUdsc1pTZ3hLU0I3RFFvSllXTmpaWEIwS0VOUFRrNHNVeWs3RFFvSmFXWW9JU2drY0dsa1BXWnZjbXNwS1NCN0RRb0pDV1JwWl" ascii
    $s15 = "$UserName = \"1337\";                                      //Your UserName here." fullword ascii
    $s16 = "$smevk = \"PD9waHAKCiRkZWZhdWx0X2FjdGlvbiA9ICdGaWxlc01hbic7CkBkZWZpbmUoJ1NFTEZfUEFUSCcsIF9fRklMRV9fKTsKaWYoIHN0cnBvcygkX1NFUlZFU" ascii
    $s17 = "$Theme = '#09B5A6';                                    //Change border-color accoriding to your choice." fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 300KB and
      (8 of them)
    ) or (all of them)
}