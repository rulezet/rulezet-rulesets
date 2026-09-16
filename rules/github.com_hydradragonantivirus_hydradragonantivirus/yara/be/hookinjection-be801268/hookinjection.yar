import "pe"
rule HookInjection {
  condition:
    (
            (uint32(0) == 0x00EC8B55 and (pe.exports("SetWindowsHookExA") or pe.exports("SetWindowsHookExW")))

            or (uint32(0) == 0x00EC8B55 and (pe.exports("UnhookWindowsHookEx")))

            or (uint32(0) == 0x00EC8B55 and (pe.exports("CallNextHookEx")))
    )
}