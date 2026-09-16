rule TTP_XOR_QUAD_CurrentVersionRun_bcb3 {
  strings:
    $key_bcb3 = { ef dc [2] cb d2 [2] e0 fe [2] ce dc [2] da c7 [2] d5 dd [2] cb c0 [2] c9 c1 [2] d2 c7 [2] ce c0 [2] d2 ef }

  condition:
    any of them
}