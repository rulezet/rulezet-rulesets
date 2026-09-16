rule PEiD_01742_Pohernah_Crypter_V1_0_1____Kas_
{
    meta:
        description = "[Pohernah Crypter V1.0.1 -> Kas]"
        ep_only = "true"
    strings:
        $a = {60 E8 00 00 00 00 5D 81 ED F1 26 40 00 8B BD 18 28 40 00 8B 8D 20 28 40 00 B8 38 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 1C 28 40 00 31 C0 51 31 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 1C 28 40 00 8B 85 24}
    condition:
        $a
}