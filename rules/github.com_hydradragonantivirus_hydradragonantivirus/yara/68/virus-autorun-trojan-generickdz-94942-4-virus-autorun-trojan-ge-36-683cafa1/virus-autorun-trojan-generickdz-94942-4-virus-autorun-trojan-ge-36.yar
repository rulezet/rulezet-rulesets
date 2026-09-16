import "pe"
rule _Virus_Autorun_Trojan_GenericKDZ_94942_4_Virus_Autorun_Trojan_Ge_36 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Trojan.GenericKDZ.94942_4.vir, Virus.Autorun_Trojan.GenericKDZ.94942_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42856ebb178057d425b0915032faa9243a470593208790861c68cd3115a13240"
    hash2       = "f424124429184fcce5f03de260e2a123484d1943b89552c527f43cf7d593794c"

  strings:
    $x1  = "  upgrade = \"-y -whatif -? --pre --version='' --except='' --params='' --install-arguments='' --override-arguments --ignore-depe" ascii
    $x2  = "  install = \"-y -whatif -? --pre --version= --params='' --install-arguments='' --override-arguments --ignore-dependencies --sou" ascii
    $x3  = "$allcommands = \" --debug --verbose --trace --noop --help --accept-license --confirm --limit-output --no-progress --log-file='' " ascii
    $x4  = "Proxy Password - Explicit proxy password (optional) to be used with username. Requires explicity proxy (`--proxy` or config sett" wide
    $x5  = "* Get-BinRoot - this is a horribly named function that doesn't do what new folks think it does. It gets you the 'tools' root, wh" wide
    $x6  = "Scripts Check $LastExitCode (external commands) - Leave this off unless you absolutely need it while you fix your package script" wide
    $x7  = "  download = \"--internalize --internalize-all-urls --ignore-dependencies --installed-packages --ignore-unfound-packages --resou" ascii
    $x8  = "  search = \"--pre --exact --by-id-only --id-starts-with --detailed --approved-only --not-broken --source='' --user='' --passwor" ascii
    $x9  = " elevated shell. When you open the command shell, you should ensure " fullword wide
    $x10 = "<!-- It is especially important to read the above link to understand additional requirements when publishing packages to the com" wide
    $x11 = "Proxy User Name - Explicit proxy user (optional). Requires explicity proxy (`--proxy` or config setting). Overrides the default " wide
    $s12 = "his package is likely not broken for licensed users - see https://chocolatey.org/docs/features-private-cdn.\"" fullword ascii
    $s13 = "* Uninstall-BinFile - used for non-exe files - executables are automatically shimmed - see https://chocolatey.org/docs/helpers-u" wide
    $s14 = "* nuget.exe can still install packages with those elements but they are ignored. Any authoring tools or commands will error on t" wide
    $s15 = "The Debugger Type Proxy failed to initialize. For the debugger diagnostics to work, the SimpleInjector.Diagnostics.dll is needed" wide
    $s16 = "Proxy Bypass On Local - Bypass proxy for local connections. Requires explicity proxy (`--proxy` or config setting). Overrides th" wide
    $s17 = "  outdated = \"-? --source='' --user='' --password='' --ignore-pinned --ignore-unfound --pre --prerelease --disable-package-repo" ascii
    $s18 = "# The command will be elevated to admin priviledges." fullword ascii
    $s19 = "The environemnt variable target scope. This is `Process`, `User`, or" fullword ascii
    $s20 = " * ChocolateyPackageParametersSensitive - Package parameters passed from command line `--package-parameters-senstivite` that are" wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c9bb752e0590e5c1059bbf7387113918" and (1 of ($x*) and all of them)
    ) or (all of them)
}