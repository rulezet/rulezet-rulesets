rule TTP_XOR_QUAD_CurrentVersionRun_df21 {
  strings:
    $key_df21 = { 8c 4e [2] a8 40 [2] 83 6c [2] ad 4e [2] b9 55 [2] b6 4f [2] a8 52 [2] aa 53 [2] b1 55 [2] ad 52 [2] b1 7d }

  condition:
    any of them
}