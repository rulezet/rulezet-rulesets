import "pe"
rule PEiD_01526_PE_PACK_v1_0_by_ANAKiN_1998_______
{
    meta:
        description = "[PE-PACK v1.0 by ANAKiN 1998 (???)]"
        ep_only = "true"
    strings:
        $a = {74 ?? E9 ?? ?? ?? ?? 00 00 00 00}
    condition:
        $a at pe.entry_point
}