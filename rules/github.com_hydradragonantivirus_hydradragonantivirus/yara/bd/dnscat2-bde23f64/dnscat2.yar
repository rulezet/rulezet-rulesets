rule dnscat2 {
  meta:
    description   = "Detection patterns for the tool 'dnscat2' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "dnscat2"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1  = /\.\/dnscat/ nocase ascii wide
            $string2  = /\/dnscat\.c/ nocase ascii wide
            $string3  = /\/dnscat2\.git/ nocase ascii wide
            $string4  = /0\.0\.0\.0:53531/ nocase ascii wide
            $string5  = /127\.0\.0\.1:53531/ nocase ascii wide
            $string6  = /data\/wordlist_256\.txt/ nocase ascii wide
            $string7  = /dnscat\s\-/ nocase ascii wide
            $string8  = /dnscat\stcpcat/ nocase ascii wide
            $string9  = /dnscat2.*\.tar\.bz2/ nocase ascii wide
            $string10 = /dnscat2\-.*\.zip/ nocase ascii wide
            $string11 = /dnscat2\./ nocase ascii wide
            $string12 = /dnscat2\// nocase ascii wide
            $string13 = /dnscat2\-server/ nocase ascii wide
            $string14 = /dnscat2\-win32\.exe/ nocase ascii wide
            $string15 = /dnsmastermind\.rb/ nocase ascii wide
            $string16 = /localhost:53531/ nocase ascii wide
            $string17 = /server\=.*port\=53531/ nocase ascii wide

  condition:
    any of them
}