rule theme_MH370 {
    meta:
	author = "MalwareTracker.com @mwtracker"
	reference = "http://blog.malwaretracker.com/2014/04/cve-2012-0158-in-mime-html-mso-format.html"
        version = "1.0"
        date = "2014-04-09"
    strings:
        $callsign1 = "MH370" ascii wide nocase fullword
        $callsign2 = "MAS370" ascii wide nocase fullword
        $desc1 = "Flight 370" ascii wide nocase fullword
    condition:
        any of them
}