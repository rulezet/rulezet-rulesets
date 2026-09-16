rule TTP_XOR_QUAD_CurrentVersionRun_d9d1 {
  strings:
    $key_d9d1 = { 8a be [2] ae b0 [2] 85 9c [2] ab be [2] bf a5 [2] b0 bf [2] ae a2 [2] ac a3 [2] b7 a5 [2] ab a2 [2] b7 8d }

  condition:
    any of them
}