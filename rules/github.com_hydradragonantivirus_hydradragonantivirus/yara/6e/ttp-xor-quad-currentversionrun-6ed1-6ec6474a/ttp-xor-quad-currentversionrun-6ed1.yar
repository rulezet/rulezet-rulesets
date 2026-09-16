rule TTP_XOR_QUAD_CurrentVersionRun_6ed1 {
  strings:
    $key_6ed1 = { 3d be [2] 19 b0 [2] 32 9c [2] 1c be [2] 08 a5 [2] 07 bf [2] 19 a2 [2] 1b a3 [2] 00 a5 [2] 1c a2 [2] 00 8d }

  condition:
    any of them
}