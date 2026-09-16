rule TTP_XOR_QUAD_CurrentVersionRun_efd1 {
  strings:
    $key_efd1 = { bc be [2] 98 b0 [2] b3 9c [2] 9d be [2] 89 a5 [2] 86 bf [2] 98 a2 [2] 9a a3 [2] 81 a5 [2] 9d a2 [2] 81 8d }

  condition:
    any of them
}