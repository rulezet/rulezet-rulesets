rule PEiD_00497_dUP_v2_x_Patcher_____www_diablo2oo2_cjb_net_
{
    meta:
        description = "[dUP v2.x Patcher --> www.diablo2oo2.cjb.net]"
        ep_only = "false"
    strings:
        $a = {54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F}
    condition:
        $a
}