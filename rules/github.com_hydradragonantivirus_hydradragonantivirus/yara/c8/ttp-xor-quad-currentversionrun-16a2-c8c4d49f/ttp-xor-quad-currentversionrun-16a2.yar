rule TTP_XOR_QUAD_CurrentVersionRun_16a2 {
  strings:
    $key_16a2 = { 45 cd [2] 61 c3 [2] 4a ef [2] 64 cd [2] 70 d6 [2] 7f cc [2] 61 d1 [2] 63 d0 [2] 78 d6 [2] 64 d1 [2] 78 fe }

  condition:
    any of them
}