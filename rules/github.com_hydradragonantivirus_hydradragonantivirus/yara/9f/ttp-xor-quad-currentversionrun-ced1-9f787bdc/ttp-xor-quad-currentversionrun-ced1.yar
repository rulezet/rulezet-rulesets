rule TTP_XOR_QUAD_CurrentVersionRun_ced1 {
  strings:
    $key_ced1 = { 9d be [2] b9 b0 [2] 92 9c [2] bc be [2] a8 a5 [2] a7 bf [2] b9 a2 [2] bb a3 [2] a0 a5 [2] bc a2 [2] a0 8d }

  condition:
    any of them
}