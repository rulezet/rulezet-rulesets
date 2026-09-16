rule PEiD_03407_Vx__Necropolis_
{
    meta:
        description = "[Vx: Necropolis]"
        ep_only = "true"
    strings:
        $a = {50 FC AD 33 C2 AB 8B D0 E2 F8}
    condition:
        $a
}