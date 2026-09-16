rule TTP_XOR_QUAD_CurrentVersionRun_d891 {
  strings:
    $key_d891 = { 8b fe [2] af f0 [2] 84 dc [2] aa fe [2] be e5 [2] b1 ff [2] af e2 [2] ad e3 [2] b6 e5 [2] aa e2 [2] b6 cd }

  condition:
    any of them
}