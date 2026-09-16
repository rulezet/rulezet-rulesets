rule PEiD_00024_ABC_Cryptor_1_0___by_ZloY_
{
    meta:
        description = "[ABC Cryptor 1.0 - by ZloY]"
        ep_only = "true"
    strings:
        $a = {68 FF 64 24 F0 68 58 58 58 58 90 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68 ?? ?? ?? ?? BF 00 ?? ?? ?? B9 00 ?? ?? ?? 80 37 ?? 47 39 CF 75 F8}
    condition:
        $a
}