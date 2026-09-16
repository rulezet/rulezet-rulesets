rule TTP_XOR_WriteProcessMemory_eda8 {
  strings:
    $key_eda8 = { ba da [2] 88 f8 [2] 8e cd [2] a0 cd [2] 9f d1 }

  condition:
    any of them
}