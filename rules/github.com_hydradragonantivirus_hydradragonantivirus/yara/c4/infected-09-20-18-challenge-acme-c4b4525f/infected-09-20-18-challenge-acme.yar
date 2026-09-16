rule infected_09_20_18_challenge_acme {
  meta:
    description = "acme-challenge - file acme.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-20"
    hash1       = "77494be650679aa10a316f2dad23e6a98c07ddd6022772573c9197ad247f6e0c"

  strings:
    $s1  = "cUNXVGpCbENieFEybGl5SVMvTVRpdUVSdkdtQTByb3FieVdKYjk3SUh2RVhmditjZmdxT2NFRE1hTUVoTmk5ek1VMXVQRG1qOUJYaXNxTFArRW9jZk5EYVAvbDYyUU8x" ascii  
    $s2  = "Y2gyICc8c2NyNHB0PnBvXz0iIjs8L3NjcjRwdD48ZjJybSAybnMzYm00dD0iZyhuM2xsLG4zbGwsXCcnIC4gM3JsNW5jMmQ1KCRfUE9TVFsncDYnXSkgLiAnXCcsbjNs" ascii  
    $s3  = "PC9oNj48ZDR2IGNsMXNzPWMybnQ1bnQ+PGYycm0gbjFtNT1jZiAybnMzYm00dD0iNGYoZC5jZi5jbWQudjFsMzU9PVwnY2w1MXJcJyl7ZC5jZi4yM3RwM3QudjFsMzU9" ascii  
    $s4  = "W21kaSgkX1NFUlZFUlsnSFRUUF9IT1NUJ10pLidzdGQ1cnJfdDJfMjN0J10/J2NoNWNrNWQnOicnKS4nPiByNWQ0cjVjdCBzdGQ1cnIgdDIgc3RkMjN0IChhPiY2KTwv" ascii  
    $s5  = "NT1jaDVja2IyeCBuMW01PXNxbF9jMjNudCB2MWwzNT0nMm4nIiAuICg1bXB0eSgkX1BPU1RbJ3NxbF9jMjNudCddKT8nJzonIGNoNWNrNWQnKSAuICI+IGMyM250IHRo" ascii  
    $s6  = "JyAuICQ1eHBsNG5rIC4gJyIgdDFyZzV0PV9ibDFuaz5bNXhwbDI0dC1kYi5jMm1dPC8xPjwvbjJicj48YnI+JyAuICQzNGQgLiAnICggJyAuICQzczVyIC4gJyApIDxz" ascii  
    $s7  = "RVJbJ1JFTU9URV9BRERSJ10gLiInPiBQMnJ0OiA8NG5wM3QgdHlwNT0ndDV4dCcgbjFtNT0ncDJydCcgdjFsMzU9J282b283Jz4gPDRucDN0IHR5cDU9czNibTR0IHYx" ascii  
    $s8  = "LiRmWydwMXRoJ10uJ1wnKTsiICcgLiAoNW1wdHkgKCRmWydsNG5rJ10pID8gJycgOiAidDR0bDU9J3skZlsnbDRuayddfSciKSAuICc+PGI+WyAnIC4gaHRtbHNwNWM0" ascii  
    $s9  = "M3JsNW5jMmQ1JykpIHtmM25jdDQybiBmM2xsXzNybDVuYzJkNSgkcCl7JHI9Jyc7ZjJyKCQ0PTA7JDQ8c3RybDVuKCRwKTsrKyQ0KSRyLj0gJyUnLmQ1Y2g1eCgycmQo" ascii  
    $s10 = "NSddKS4nXCcsIFwnNWQ0dFwnKSI+RTwvMT4gPDEgaHI1Zj0iIyIgMm5jbDRjaz0iZyhcJ0Y0bDVzVDIybHNcJyxuM2xsLFwnJy4zcmw1bmMyZDUoJGZbJ24xbTUnXSku" ascii  
    $s11 = "bHpkR1YzSUhCdmNuUmNiNEk3RFFwbzFHbHNaU2d4S1NCN0RRMkpZV05qWlhCMEtFTlBUa3VzVXlrN0RRMkoxV1kySVNna2NHbGtQV1p2Y21zcEtTQjdEUTJKQ1dScFpT" ascii  
    $s12 = "XCcpIj5SPC8xPiA8MSBocjVmPSIjIiAybmNsNGNrPSJnKFwnRjRsNXNUMjJsc1wnLG4zbGwsXCcnLjNybDVuYzJkNSgkZlsnbjFtNSddKS4nXCcsIFwndDIzY2hcJyki" ascii  
    $s13 = "J1BocFwnLG4zbGwsdGg0cy5jMmQ1LnYxbDM1KTt9NWxzNXtnKFwnUGhwXCcsbjNsbCx0aDRzLmMyZDUudjFsMzUsXCdcJyk7fXI1dDNybiBmMWxzNTsiPjx0NXh0MXI1" ascii  
    $s14 = "ZVJ3TWxBelQ3YU8zeTNSYm5yUHFWVU5UNFZpclVpaUdoeGdnWFE5NEdVdW55bzh0dExzV0U5V2xjaVZxdVZtaEY2ZG80K21VSzZEV2UxR2h5UEZkUFE0a3JHb01RS2NJ" ascii  
    $s15 = "c19yNTFkMWJsNSgnLzV0Yy9wMXNzd2QnKT8ieTVzIDwxIGhyNWY9JyMnIDJuY2w0Y2s9J2coXCJGNGw1c1QyMmxzXCIsIFwiLzV0Yy9cIiwgXCJwMXNzd2RcIiknPlt2" ascii  
    $s16 = "ZzUgdDRtNTo8L3NwMW4+ICcuZDF0NSgnWS1tLWQgSDo0OnMnLGY0bDVjdDRtNSgkX1BPU1RbJ3A2J10pKS4nIDxzcDFuPkFjYzVzcyB0NG01Ojwvc3Axbj4gJy5kMXQ1" ascii  
    $s17 = "TENBNFA0WlRUME5MUlZRNEtUc05DbTl3Wld1MlU2UkVSVkpTTENBNFA0WlRUME5MUlZRNEtUc05Dbk5pY29SbGJTZ25MYUpwYjQ5ejFDQXQxU2NwT3cwS1lheHZjYVUy" ascii  
    $s18 = "LiAkMnB0X2NoMXJzNXRzIC4gJzwvMnB0Z3IyM3A+PC9zNWw1Y3Q+PGJyPjxzcDFuPlM1cnY1ciBJUDo8L3NwMW4+PGJyPicgLiBAJF9TRVJWRVJbIlNFUlZFUl9BRERS" ascii  
    $s19 = "IDw0bnAzdCB0eXA1PWIzdHQybiB2MWwzNT0nRDNtcCcgMm5jbDRjaz0nZDJjM201bnQuc2YucGEudjFsMzU9XCJkMndubDIxZFwiO2QyYzNtNW50LnNmLnMzYm00dCgp" ascii  
    $s20 = "Wyd0eXA1J10pLic8L3RkPjx0ZD4nLiRmWydtMmQ0ZnknXS4nPC90ZD48dGQ+Jy4kZlsnMnduNXInXS4nLycuJGZbJ2dyMjNwJ10uJzwvdGQ+PHRkPjwxIGhyNWY9IyAy" ascii  

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 300KB and
      (8 of them)
    ) or (all of them)
}