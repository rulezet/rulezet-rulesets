rule TTP_XOR_QUAD_CurrentVersionRun_eaff {
  strings:
    $key_eaff = { b9 90 [2] 9d 9e [2] b6 b2 [2] 98 90 [2] 8c 8b [2] 83 91 [2] 9d 8c [2] 9f 8d [2] 84 8b [2] 98 8c [2] 84 a3 }

  condition:
    any of them
}