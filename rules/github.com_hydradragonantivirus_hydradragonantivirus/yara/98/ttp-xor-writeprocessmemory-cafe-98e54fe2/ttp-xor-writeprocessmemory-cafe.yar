rule TTP_XOR_WriteProcessMemory_cafe {
  strings:
    $key_cafe = { 9d 8c [2] af ae [2] a9 9b [2] 87 9b [2] b8 87 }

  condition:
    any of them
}