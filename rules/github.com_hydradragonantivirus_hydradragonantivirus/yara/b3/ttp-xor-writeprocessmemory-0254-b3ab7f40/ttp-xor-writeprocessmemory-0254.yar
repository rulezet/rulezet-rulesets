rule TTP_XOR_WriteProcessMemory_0254 {
  strings:
    $key_0254 = { 55 26 [2] 67 04 [2] 61 31 [2] 4f 31 [2] 70 2d }

  condition:
    any of them
}