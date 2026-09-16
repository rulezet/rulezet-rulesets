rule LinkuryBSample
{
    meta:
        Description = "Adware.Linkury.B.vb"
        ThreatLevel = "5"

    strings:
        $ = "C:\\Cranberry\\bin\\CaraDelevigne\\Cara.pdb" ascii wide

    condition:
        any of them
}