import "pe"
rule WWPACK_v3_02__v3_02a__v3_04__Relocations_pack_ {
  strings:
    $a0 = { BE ?? ?? BF ?? ?? B9 ?? ?? 8C CD 81 ED ?? ?? 8B DD 81 EB ?? ?? 8B D3 FC FA 1E 8E DB 01 15 33 C0 2E AC }

  condition:
    $a0 at pe.entry_point
}