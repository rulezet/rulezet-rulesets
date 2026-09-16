import "pe"
rule PEiD_01625_PENinja_
{
    meta:
        description = "[PENinja]"
        ep_only = "true"
    strings:
        $a = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
    condition:
        $a at pe.entry_point
}