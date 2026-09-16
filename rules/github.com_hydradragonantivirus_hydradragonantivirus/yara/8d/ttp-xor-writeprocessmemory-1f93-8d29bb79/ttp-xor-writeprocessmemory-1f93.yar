rule TTP_XOR_WriteProcessMemory_1f93 {
  strings:
    $key_1f93 = { 48 e1 [2] 7a c3 [2] 7c f6 [2] 52 f6 [2] 6d ea }

  condition:
    any of them
}