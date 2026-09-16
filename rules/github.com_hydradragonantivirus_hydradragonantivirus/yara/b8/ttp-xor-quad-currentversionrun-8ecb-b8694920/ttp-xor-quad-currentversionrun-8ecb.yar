rule TTP_XOR_QUAD_CurrentVersionRun_8ecb {
  strings:
    $key_8ecb = { dd a4 [2] f9 aa [2] d2 86 [2] fc a4 [2] e8 bf [2] e7 a5 [2] f9 b8 [2] fb b9 [2] e0 bf [2] fc b8 [2] e0 97 }

  condition:
    any of them
}