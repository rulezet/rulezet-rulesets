rule PEiD_00913_INCrypter_0_3__INinY____by_z3e_NiFe_
{
    meta:
        description = "[INCrypter 0.3 (INinY) - by z3e_NiFe]"
        ep_only = "true"
    strings:
        $a = {60 64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8D 58 20 C7 03 00 00 00 00 E8 00 00 00 00 5D 81 ED 4D 16 40 00 8B 9D 0E 17 40 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 83 F8 01 75 05 03 DB C1 CB 10 8B 8D 12 17 40 00 8B B5 06 17 40 00 51 81 3E 2E 72 73 72 74 65 8B}
    condition:
        $a
}