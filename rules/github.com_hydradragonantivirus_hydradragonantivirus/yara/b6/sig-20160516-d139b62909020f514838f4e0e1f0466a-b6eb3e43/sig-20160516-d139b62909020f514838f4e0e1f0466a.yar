rule sig_20160516_d139b62909020f514838f4e0e1f0466a {
  meta:
    description = "datamaliciousorder - file 20160516_d139b62909020f514838f4e0e1f0466a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b2ec59bc2be2740b568290fa13920d662567a51d8448b9f86ff1cce25dd8fa6"

  strings:
    $s1  = "var standard = [calculate, consign,retrieve,  \"\"+\".\"+(\"eleven\",\"tournaments\",\"nightcap\",\"mourner\",\"meetup\",\"corve" ascii
    $s2  = "        columbus[(alligator + \"o\"+(\"gasoline\",\"palatine\",\"foothold\",\"shortcuts\",\"spine\",\"presidency\",\"georgie\"," ascii
    $s3  = "primer = ((\"charlie\", \"programming\", \"gradation\", \"incontrovertible\", \"sRdOQhBzTvKM\") + \"GKwqQjMbFx\").testimony2();" fullword ascii
    $s4  = "alligator = ((\"saved\", \"currants\", \"trigger\", \"quandary\", \"psFRQYC\") + \"KyRCuCpzKW\").testimony2();" fullword ascii
    $s5  = "champion = champion+ standard.shift();" fullword ascii
    $s6  = "String.prototype.testimony2 = function () {" fullword ascii
    $s7  = "String.prototype.testimony4 = function() {" fullword ascii
    $s8  = "String.prototype.testimony = function () {" fullword ascii
    $s9  = "var standard = [calculate, consign,retrieve,  \"\"+\".\"+(\"eleven\",\"tournaments\",\"nightcap\",\"mourner\",\"meetup\",\"corve" ascii
    $s10 = "var quicksilver = {" fullword ascii
    $s11 = "  obituary = [];" fullword ascii
    $s12 = "var resist = 0;" fullword ascii
    $s13 = "var consign =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".testimony4();" fullword ascii
    $s14 = "var retrieve =\"JVRFTVAl\".testimony4();" fullword ascii
    $s15 = "var establishing = this[standard.shift()];" fullword ascii
    $s16 = "var heredity = 6/6;" fullword ascii
    $s17 = "rewdness\",\"introduces\",\"donor\",\"grandpa\",\"irwin\",\"goodfellowship\",\"intermediary\",\"08\"), primer)] = 0;" fullword ascii
    $s18 = "weasel = ((\"caper\", \"alertness\", \"registration\", \"swans\", \"EXIkQWlxqWVq\") + \"rARKiwkp\").testimony2();" fullword ascii
    $s19 = "for (var i in quicksilver){sticker = sticker.replace(i, quicksilver[i]);}" fullword ascii
    $s20 = "losses[standard.shift()](champion, heredity, true);hozDhkngH = \"_F17_\";" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}