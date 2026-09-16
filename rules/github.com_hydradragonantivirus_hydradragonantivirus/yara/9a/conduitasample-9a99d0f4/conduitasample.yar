rule ConduitASample
{
    meta:
        Description = "Adware.Conduit.A.vb"
        ThreatLevel = "5"

    strings:
		$ = "GetSpeedBrowserInstalled" ascii wide
		$ = "SpeedBrowserAlreadyInstalled" ascii wide
		$ = "Injekt SVN - client" ascii wide

    condition:
        any of them
}