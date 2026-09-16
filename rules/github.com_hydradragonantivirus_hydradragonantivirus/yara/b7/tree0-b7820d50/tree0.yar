rule tree0 {
  strings:
    $s0    = "changeFileOwner2" fullword
    $s1    = "didFailToRegisterForRemoteNotificationsWithError" fullword
    $s2    = "allItemsWithItemClass" fullword
    $s3    = "NSUndoManagerProxy" fullword
    $s4    = "N10cryptonote14tx" fullword
    $s5    = "N7leveldb8SnapshotE" fullword
    $s6    = "setButton1Action" fullword
    $s7    = "ZBSystemInformation" fullword
    $s8    = "RequestFPGACount" fullword
    $s9    = "krAttachHTTPForm" fullword
    $s10   = "updateMenuEntryTokenWithTotalScanSize" fullword
    $s11   = "allocatorI11FILE" fullword
    $s12   = "NetworkExtension" fullword
    $s13   = "20191105000000Z0" fullword
    $s14   = "NSAppleEventManager" fullword
    $s15   = "getAuthorization" fullword
    $s16   = "ZBWebViewController" fullword
    $s17   = "IORegistryEntryFromPath" fullword
    $s18   = "ZTSN10CryptoNote29KVBinaryInputStreamSerializerE" fullword
    $s19   = "LinkEqualizationRequest" fullword
    $s20   = "KGCustButtonView" fullword
    $s21   = "makeNewConnection" fullword
    $s22   = "errcallEPPFvPK5DbEnvPKcS4" fullword
    $s23   = "ZBLocalizedString" fullword
    $s24   = "textForMessageInDraggedView" fullword
    $s25   = "12CrtAllocatorELj0EE12PrettyPrefixENS" fullword
    $s26   = "ZN2cv10AutoBufferIhLm4104EE8allocateEm" fullword
    $s27   = "setNotificationsCompletionHandler" fullword
    $s28   = "140129192647Z0A1" fullword
    $s29   = "getCursorPosition" fullword
    $s30   = "11checkObjectERKNSt3" fullword
    $s31   = "applyMacKeeperFlatDesign" fullword
    $s32   = "sizeOfItemAtPath" fullword
    $s33   = "JKArrayRemoveObjectAtIndex" fullword
    $s34   = "djwIcRRRRRRRRRRRRRRK" fullword
    $s35   = "CFBundleIdentifier" fullword
    $s36   = "overrideYahooURL" fullword
    $s37   = "ZZ16SelectBaseParamsN16CBaseChainParams7NetworkEE8" fullword
    $s38   = "arrayWithJSONStringIgnoringNulls" fullword
    $s39   = "kZBZeoAccountLoggedInNotification" fullword
    $s40   = "enumerationMutation" fullword
    $s42   = "redirectResponse" fullword
    $s43   = "HMHMHMHMHMHMHMHMH" fullword
    $s44   = "CFNumberGetValue" fullword
    $s45   = "UHAWAVAUATSH8LMHMHUHuHH" fullword
    $s46   = "isAppStoreDistribution" fullword
    $s47   = "270201221215Z0y1" fullword
    $s48   = "stringWithFormat" fullword
    $s49   = "x2fvpr854319l6k9d06xlwt0rqm9vf" fullword
    $s50   = "certificateauthority0" fullword
    $s51   = "ddddddddddddddddddddddddddddddddsd" fullword
    $s52   = "fileHandleForReading" fullword
    $s53   = "defaultSessionConfiguration" fullword
    $s54   = "UHAWAVAUATSHHHuE" fullword
    $s55   = "UIViewController" fullword
    $s56   = "retainAutoreleasedReturnValue" fullword
    $s57   = "IHEHEHEHEHEHEHEL" fullword
    $s58   = "libswiftDispatch" fullword
    $s59   = "UserNotifications" fullword
    $s60   = "CSo12NSDictionary" fullword
    $s62   = "ServiceManagement" fullword
    $s63   = "350209214036Z0b1" fullword
    $s64   = "CFConstantStringClassReference" fullword
    $s65   = "loadWeakRetained" fullword
    $s66   = "abcdefghijklmnopqrstuvwxyz" fullword
    $s67   = "OSAtomicDecrement32" fullword
    $s68   = "libswiftCoreFoundation" fullword
    $s69   = "numberWithDouble" fullword
    $s70   = "debugDescription" fullword
    $s71   = "PrivateFrameworks" fullword
    $s72   = "autoreleaseReturnValue" fullword
    $s73   = "retainAutorelease" fullword
    $s74   = "UHAWAVAUATSH8IIH" fullword
    $s75   = "NSNotificationCenter" fullword
    $s76   = "ZTSN5boost9exceptionE" fullword
    $s77   = "CFArrayGetValueAtIndex" fullword
    $s78   = "ApplicationServices" fullword
    $s79   = "lswiftObjectiveC" fullword
    $s80   = "IOIteratorIsValid" fullword
    $s81   = "DefaultRuneLocale" fullword
    $s82   = "MobileCoreServices" fullword
    $s83   = "arrayWithObjects" fullword
    $s85   = "ZN9QListData7disposeEPNS" fullword
    $s86   = "FromStringAndSize" fullword
    $s87   = "iPhoneSimulator10" fullword
    $s88   = "ZN7QObject10childEventEP11QChildEvent" fullword
    $s89   = "9allocatorIcEEEE" fullword
    $s90   = "retainAutoreleaseReturnValue" fullword
    $s91   = "SystemConfiguration" fullword
    $s109  = "NSStringFromClass" fullword
    $s110  = "copyElephantBrain" fullword
    $s113  = "localizedStringForKey" fullword
    $s145  = "category23default" fullword
    $s146  = "EHMHMHMHMHMHMHMHMHMHMH" fullword
    $s147  = "HuHUHEHHMHMHMHMHUHuHHuHHUH" fullword
    $s148  = "dictionaryWithContentsOfFile" fullword
    $s149  = "componentsSeparatedByString" fullword
    $s151  = "HMHMHMHMHMHMHMHML" fullword
    $s154  = "kCFAllocatorDefault" fullword
    $s156  = "NSAutoreleasePool" fullword
    $s157  = "isAccessibilityElement" fullword
    $s162  = "replaceCharactersInRange" fullword
    $s163  = "certificateauthority" fullword
    $s164  = "CFURLGetFileSystemRepresentation" fullword
    $s166  = "UHAWAVAUATSPIHIH" fullword
    $s168  = "autoreleasePoolPop" fullword
    $s169  = "NSAddressOfSymbol" fullword
    $s170  = "contentsOfDirectoryAtPath" fullword
    $s171  = "CFStringCreateWithCString" fullword
    $s174  = "NSConcreteGlobalBlock" fullword
    $s175  = "ecpointformatlist" fullword
    $s176  = "sharedApplication" fullword
    $s177  = "UHAWAVAUATSPIIHt" fullword
    $s181  = "arrayWithCapacity" fullword
    $s182  = "fileExistsAtPath" fullword
    $s183  = "AECreateAppleEvent" fullword
    $s184  = "JSValueMakeUndefined" fullword
    $s186  = "UHAWAVAUATSH8IHH" fullword
    $s187  = "getInitializedObjCClass" fullword
    $s188  = "JSValueUnprotect" fullword
    $s189  = "UHAWAVAUATSPIIID" fullword
    $s190  = "removeObjectForKey" fullword
    $s191  = "traitsIcEEE3putEc" fullword
    $s192  = "CFStringGetCString" fullword
    $s193  = "ZN9QListData11shared" fullword
    $s194  = "HEHEHEHEHEHEHEHEHEHEHEHEI" fullword
    $s198  = "0123456789abcdef" fullword
    $s199  = "9allocatorIcEEE6insertEmPKcm" fullword
    $s201  = "respondsToSelector" fullword
    $s204  = "SecItemCopyMatching" fullword
    $s206  = "UHAWAVAUATSPAAII" fullword
    $s209  = "DisableThreadLibraryCalls" fullword
    $s210  = "dataUsingEncoding" fullword
    $s212  = "ImageCaptureCore" fullword
    $s297  = "stringByAppendingPathComponent" fullword
    $s298  = "CFBundleCopyBundleURL" fullword
    $s299  = "CFStringMakeConstantString" fullword
    $s315  = "conformsToProtocol" fullword
    $s358  = "dataTaskWithRequest" fullword
    $s359  = "componentsSeparatedByCharactersInSet" fullword
    $s368  = "numberWithUnsignedInt" fullword
    $s369  = "indexOfTabViewItem" fullword
    $s370  = "NSPropertyListSerialization" fullword
    $s372  = "caseInsensitiveCompare" fullword
    $s377  = "140213191008Z0A1" fullword
    $s379  = "UHAWAVAUATSPDEAI" fullword
    $s381  = "AssemblyProductAttribute" fullword
    $s382  = "MacKeeperPrivilegedHelper" fullword
    $s383  = "CFBundleGetVersionNumber" fullword
    $s385  = "CFDictionaryCreateMutable" fullword
    $s390  = "9allocatorIcEEEC1ERKS5" fullword
    $s394  = "180123004003Z0A1" fullword
    $s395  = "191127221001Z0A1" fullword
    $s398  = "UHAWAVAUATSH8IIHH" fullword
    $s400  = "191128154500Z0A1" fullword
    $s408  = "previousblockhash" fullword
    $s415  = "200219223002Z0B1" fullword
    $s416  = "AuthorizationFree" fullword
    $s469  = "ARCLiteIndexedSubscripting" fullword
    $s470  = "stringWithUTF8String" fullword
    $s489  = "getblocktemplate" fullword
    $s490  = "SafariExtensionViewController" fullword
    $s496  = "ZN9QListData6appendERKS" fullword
    $s497  = "ShCsSwSzfKpADKfADCNK" fullword
    $s499  = "20191001103003Z0" fullword
    $s500  = "cCFAttributedStringMBS" fullword
    $s501  = "kMDItemWhereFroms" fullword
    $s506  = "UHAWAVAUATSH8HIH" fullword
    $s507  = "CFURLCopyFileSystemPath" fullword
    $s509  = "efCkKaADK3CAKRCNC" fullword
    $s510  = "ZN16QLoggingCategoryD1Ev" fullword
    $s513  = "spDkrKTDKFCLC8CXD" fullword
    $s530  = "numberWithUnsignedLong" fullword
    $s531  = "replaceObjectAtIndex" fullword
    $s540  = "ZTSN5boost18thread" fullword
    $s541  = "shouldChangeCharactersInRange" fullword
    $s549  = "IOServiceGetMatchingServices" fullword
    $s550  = "getInstanceMethod" fullword
    $s553  = "selectorPFP11objc" fullword
    $s556  = "libswiftCoreGraphics" fullword
    $s561  = "210412223435Z0V1" fullword
    $s564  = "getExistentialTypeMetadata" fullword
    $s565  = "columnIndexForName" fullword
    $s571  = "traitsIcEEE9showmanycEv" fullword
    $s575  = "9allocatorIcEEEEPNS0" fullword
    $s576  = "textFieldDidEndEditing" fullword
    $s577  = "UHAWAVAUATSH8IHuIH" fullword
    $s579  = "userInterfaceIdiom" fullword
    $s582  = "UHAWAVAUATSPIHIIH" fullword
    $s585  = "NSFetchedPropertyDescription" fullword
    $s589  = "createFileAtPath" fullword
    $s612  = "glFramebufferTextureLayer" fullword
    $s661  = "certificationauthority" fullword
    $s662  = "GetDiskFreeSpace" fullword
    $s665  = "terminationStatus" fullword
    $s668  = "intrinsicContentSize" fullword
    $s671  = "StringCharCodeAt" fullword
    $s674  = "clickedButtonAtIndex" fullword
    $s678  = "mediumspringgreen" fullword
    $s744  = "enumerateObjectsUsingBlock" fullword
    $s752  = "IOCreatePlugInInterfaceForService" fullword
    $s760  = "EEEEEEEEE7disposeEv" fullword
    $s761  = "ZN7QLayout18setContentsMarginsEiiii" fullword
    $s762  = "ZNK12QMapNodeBase8nextNodeEv" fullword
    $s785  = "N5boost9exceptionE" fullword
    $s792  = "CGContextFillRect" fullword
    $s793  = "15mutex6unlockEv" fullword
    $s802  = "kCFCoreFoundationVersionNumber" fullword
    $s807  = "unzGoToFilePos64" fullword
    $s812  = "HEHEHEHEHEHEHEHE" fullword
    $s847  = "crossCertificatePair" fullword
    $s887  = "kSecMatchLimitAll" fullword
    $s912  = "GenerateConnectionID" fullword
    $s931  = "expectedContentLength" fullword
    $s932  = "resignFirstResponder" fullword
    $s938  = "CFReadStreamCreateWithFile" fullword
    $s949  = "34MutableTransactionSignatureCreator" fullword
    $s950  = "ZTVN5boost4asio5error6detail12ssl" fullword
    $s951  = "Internationalized" fullword
    $s954  = "traitsIcEEEEE16find" fullword
    $s955  = "UHAWAVAUATSH8HLg" fullword
    $s983  = "Dfllononqpqpsrr2" fullword
    $s985  = "k7kBkQkpkkkkkkkkkkflmllllll" fullword
    $s992  = "viewForHeaderInSection" fullword
    $s993  = "getTupleTypeMetadata2" fullword
    $s1009 = "fHSUATAUAVIHHIHIHD" fullword
    $s1048 = "Z83Z8CZ8SZ8cZ8sZ8" fullword
    $s1056 = "Z83Z8CZ8SZ8cZ8sZ8z" fullword
    $s1071 = "stringWithCapacity" fullword
    $s1072 = "initWithContentsOfURL" fullword
    $s1084 = "runningApplications" fullword
    $s1085 = "UHAWAVAUATSHxLMMIHHExHhHEhHpHEpHxHE" fullword
    $s1088 = "scheduledTimerWithTimeInterval" fullword
    $s1089 = "NSAssertionHandler" fullword
    $s1090 = "kSMDomainSystemLaunchd" fullword
    $s1092 = "addUndeleterFilesRecovered" fullword
    $s1105 = "withIntermediateDirectories" fullword
    $s1113 = "bundleIdentifier" fullword
    $s1118 = "dataWithContentsOfFile" fullword
    $s1120 = "numberWithUnsignedInteger" fullword
    $s1135 = "timeIntervalSinceDate" fullword
    $s1140 = "CFBundleExecutable" fullword
    $s1142 = "301231000000Z0s1" fullword
    $s1144 = "checkForUpdatesInBackground" fullword
    $s1145 = "IORegistryEntryCreateCFProperty" fullword
    $s1152 = "CFBundleShortVersionString" fullword
    $s1154 = "ContiguousaB0Vy7ElementQzGz" fullword
    $s1177 = "completionHandler" fullword
    $s1190 = "linenoiseClearScreen" fullword
    $s1228 = "setAllowedFileTypes" fullword
    $s1229 = "substringToIndex" fullword
    $s1231 = "ZN11WalletModel20getAddressTableModelEv" fullword
    $s1234 = "NSJSONSerialization" fullword
    $s1241 = "b77a5c561934e089" fullword
    $s1267 = "113EmptyIteratorE" fullword
    $s1268 = "2numBlocksChanged" fullword
    $s1270 = "tIvPFvP11ClientModelS3" fullword
    $s1281 = "SecTransformExecute" fullword
    $s1282 = "willDismissWithButtonIndex" fullword
    $s1284 = "InitializeDistributedNotification" fullword
    $s1285 = "DRGp0SARARARARARA" fullword
    $s1286 = "kZBTrialManagerDeactivatedNotification" fullword
    $s1287 = "calcDecodeLength" fullword
    $s1289 = "IntermediateBuildFilesPath" fullword
    $s1291 = "clientSocketWithRequest" fullword
    $s1292 = "getRequiredClass" fullword
    $s1293 = "setWorkspaceSessionActive" fullword
    $s1294 = "autoreleasepoolPK11mach" fullword
    $s1295 = "updatedStatusTitle" fullword
    $s1303 = "fastIndexForKnownKey" fullword
    $s1305 = "UHAWAVATSIII1Mt2Mt" fullword
    $s1307 = "UHAWAVAUATSPIIIMthMtcL" fullword
    $s1316 = "NSDistantObjectRequest" fullword
    $s1317 = "SSS10FoundationE19" fullword
    $s1319 = "ATEContentBlockersRulesWereSet" fullword
    $s1334 = "kMKBannerNotificationServiceName" fullword
    $s1335 = "kMKAlertNotificationServiceName" fullword
    $s1336 = "addEntriesFromDictionaryP11objc" fullword
    $s1337 = "setAttributedTitle" fullword
    $s1352 = "whatIsPluginDescription" fullword
    $s1355 = "SUFileOpRemoveCommand" fullword
    $s1364 = "initWithCapacity" fullword
    $s1366 = "mkPreferredLocalization" fullword
    $s1369 = "stringCompareWithSmolCheck" fullword
    $s1371 = "URLSessionDidFinishEventsForBackgroundURLSession" fullword
    $s1379 = "bridgeToObjectiveCSo5NSURLCyF" fullword
    $s1387 = "UIApplicationDidEnterBackgroundNotification" fullword
    $s1388 = "cancelButtonTitle" fullword
    $s1398 = "connectionDidFinishLoading" fullword
    $s1402 = "ZBLanguageStripperService" fullword
    $s1404 = "NSOperationQueue" fullword
    $s1407 = "convertObjCBoolToBoolFVS" fullword
    $s1413 = "ZL30NSUndoManagerProxy" fullword
    $s1423 = "clientDidConnectWithConnection" fullword
    $s1426 = "backingScaleFactor" fullword
    $s1427 = "initWithSuiteName" fullword
    $s1428 = "JKDictionaryClass" fullword
    $s1437 = "UHAWAVAUATSHHIH5M" fullword
    $s1438 = "whuplqdwhSurfhvv" fullword
    $s1439 = "stackFrameWithSymbol" fullword
    $s1440 = "setStandardInput" fullword
    $s1442 = "NSMutableURLRequest" fullword
    $s1444 = "copyClassNamesForImage" fullword
    $s1456 = "mouseLocationOutsideOfEventStream" fullword
    $s1457 = "RGp0SARARARARARA" fullword
    $s1464 = "objectForKeyP11objc" fullword
    $s1475 = "LSSharedFileListItemSetProperty" fullword
    $s1476 = "shouldDragDocumentWithEvent" fullword
    $s1478 = "CFRunLoopGetMain" fullword
    $s1490 = "dataWithJSONObject" fullword
    $s1494 = "objectAtIndexedSubscriptP7NSArrayP13objc" fullword
    $s1496 = "localizedCaseInsensitiveCompare" fullword
    $s1500 = "createDirectoryAtURL" fullword
    $s1503 = "lengthOfBytesUsingEncoding" fullword
    $s1509 = "allocBatchP11objc" fullword
    $s1515 = "UIAlertViewDelegate" fullword
    $s1522 = "conformsToProtocolEPKNS" fullword
    $s1524 = "countByEnumeratingWithState" fullword
    $s1527 = "collectingEnabled" fullword
    $s1533 = "xmlParserDelegate" fullword
    $s1539 = "DispatchOnceCounter" fullword
    $s1540 = "fileManagerByPreservingAuthorizationRights" fullword
    $s1541 = "getBrowserWindowFrame" fullword
    $s1550 = "s10Foundation3URLV19" fullword
    $s1551 = "applicationWillHide" fullword
    $s1552 = "IOConnectCallAsyncMethod" fullword
    $s1554 = "RARARARARARARARARARAZAp" fullword
    $s1568 = "touchesCancelled" fullword
    $s1582 = "JSObjectSetProperty" fullword
    $s1587 = "CGContextFillPath" fullword
    $s1589 = "N5boost9gregorian15bad" fullword
    $s1591 = "seekToFileOffset" fullword
    $s1593 = "unretainedObject" fullword
    $s1599 = "NSDistributedNotificationCenter" fullword
    $s1604 = "didUpdateUserActivity" fullword
    $s1609 = "s8Dispatch0A4TimeVMa" fullword
    $s1610 = "viewForTableColumn" fullword
    $s1615 = "systemFontOfSize" fullword
    $s1620 = "initWithIdentifier" fullword
    $s1621 = "applicationShouldHandleReopen" fullword
    $s1629 = "setStandardOutput" fullword
    $s1631 = "webScriptNameForSelector" fullword
    $s1648 = "delegateHandlesKey" fullword
    $s1662 = "continueUserActivity" fullword
    $s1679 = "timerWithTimeInterval" fullword
    $s1690 = "CSGetLocalIdentityAuthority" fullword
    $s1692 = "getInjectedParams" fullword
    $s1715 = "setRolloverImage" fullword
    $s1724 = "currentScanedItemsCount" fullword
    $s1727 = "fileHandleForWriting" fullword
    $s1728 = "invalidateShadow" fullword
    $s1729 = "AHIOPlatfoHrmUUID" fullword
    $s1732 = "willResizeForVersionBrowserWithMaxPreferredSize" fullword
    $s1748 = "ZL22copySwiftV1MangledNamePKcb" fullword
    $s1763 = "CGPathCreateMutable" fullword
    $s1773 = "SCNetworkReachabilityUnscheduleFromRunLoop" fullword
    $s1777 = "stringWithString" fullword
    $s1800 = "didFinishDownloadingToURL" fullword
    $s1802 = "performActionForShortcutItem" fullword
    $s1807 = "defaultConfiguration" fullword
    $s1812 = "NSSharingServicePicker" fullword
    $s1824 = "Z83Z8CZ8SZ8cZ8sZ82" fullword
    $s1837 = "EXUa2Kc9Qd9ysfHNqqIFg" fullword
    $s1846 = "AudioConverterGetProperty" fullword
    $s1850 = "NSURLSessionDataTask" fullword
    $s1865 = "createDragButtons" fullword
    $s1872 = "sSY8rawValue03RawB0QzvgTj" fullword
    $s1877 = "textDidEndEditing" fullword

  condition:
    ((#s0 <= 0.5)
      and ((#s1 <= 0.5)
        and ((#s2 <= 1.0)
          and ((#s3 <= 0.5)
            and ((#s4 <= 0.5)
              and ((#s5 <= 0.5)
                and ((#s6 <= 0.5)
                  and ((#s7 <= 0.5)
                    and ((#s8 <= 0.5)
                      and ((#s9 <= 0.5)
                        and ((#s10 <= 0.5)
                          and ((#s11 <= 2.0)
                            and ((#s12 <= 1.5)
                              and ((#s13 <= 0.5)
                                and ((#s14 <= 0.5)
                                  and ((#s15 <= 1.0)
                                    and ((#s16 <= 0.5)
                                      and ((#s17 <= 1.5)
                                        and ((#s18 <= 0.5)
                                          and ((#s19 <= 0.5)
                                            and ((#s20 <= 0.5)
                                              and ((#s21 <= 0.5)
                                                and ((#s22 <= 0.5)
                                                  and ((#s23 <= 0.5)
                                                    and ((#s24 <= 0.5)
                                                      and ((#s25 <= 0.5)
                                                        and ((#s26 <= 2.0)
                                                          and ((#s27 <= 0.5)
                                                            and ((#s28 <= 0.5)
                                                              and ((#s29 <= 0.5)
                                                                and ((#s30 <= 0.5)
                                                                  and ((#s31 <= 0.5)
                                                                    and ((#s32 <= 0.5)
                                                                      and ((#s33 <= 0.5)
                                                                        and ((#s34 <= 0.5)
                                                                          and ((#s35 <= 0.5)
                                                                            and ((#s36 <= 1.0)
                                                                              and ((#s37 <= 1.0)
                                                                                and ((#s38 <= 0.5)
                                                                                  and ((#s39 <= 1.0)
                                                                                    and ((#s40 <= 0.5)
                                                                                      and ((filesize <= 49998.0)
                                                                                        and ((#s42 <= 0.5)
                                                                                          and ((#s43 <= 0.5)
                                                                                            and ((#s44 <= 0.5)
                                                                                              and ((#s45 <= 0.5)
                                                                                                and ((#s46 <= 0.5)
                                                                                                  and ((#s47 <= 0.5)
                                                                                                    and ((#s48 <= 0.5)
                                                                                                      and ((#s49 <= 0.5)
                                                                                                        and ((#s50 <= 0.5)
                                                                                                          and ((#s51 <= 0.5)
                                                                                                            and ((#s52 <= 0.5)
                                                                                                              and ((#s53 <= 0.5)
                                                                                                                and ((#s54 <= 0.5)
                                                                                                                  and ((#s55 <= 0.5)
                                                                                                                    and ((#s56 <= 0.5)
                                                                                                                      and ((#s57 <= 0.5)
                                                                                                                        and ((#s58 <= 0.5)
                                                                                                                          and ((#s59 <= 1.5)
                                                                                                                            and ((#s60 <= 0.5)
                                                                                                                              and ((filesize <= 16468.0)
                                                                                                                                and ((#s62 <= 1.0)
                                                                                                                                  and ((#s63 <= 0.5)
                                                                                                                                    and ((#s64 <= 0.5)
                                                                                                                                      and ((#s65 <= 0.5)
                                                                                                                                        and ((#s66 <= 0.5)
                                                                                                                                          and ((#s67 <= 0.5)
                                                                                                                                            and ((#s68 <= 0.5)
                                                                                                                                              and ((#s69 <= 0.5)
                                                                                                                                                and ((#s70 <= 1.0)
                                                                                                                                                  and ((#s71 <= 0.5)
                                                                                                                                                    and ((#s72 <= 0.5)
                                                                                                                                                      and ((#s73 <= 0.5)
                                                                                                                                                        and ((#s74 <= 0.5)
                                                                                                                                                          and ((#s75 <= 4.5)
                                                                                                                                                            and ((#s76 <= 0.5)
                                                                                                                                                              and ((#s77 <= 1.0)
                                                                                                                                                                and ((#s78 <= 0.5)
                                                                                                                                                                  and ((#s79 <= 0.5)
                                                                                                                                                                    and ((#s80 <= 1.0)
                                                                                                                                                                      and ((#s81 <= 0.5)
                                                                                                                                                                        and ((#s82 <= 1.0)
                                                                                                                                                                          and ((#s83 <= 0.5)
                                                                                                                                                                            and ((filesize <= 12530.0)
                                                                                                                                                                              and ((#s85 <= 0.5)
                                                                                                                                                                                and ((#s86 <= 1.0)
                                                                                                                                                                                  and ((#s87 <= 1.5)
                                                                                                                                                                                    and ((#s88 <= 0.5)
                                                                                                                                                                                      and ((#s89 <= 1.0)
                                                                                                                                                                                        and ((#s90 <= 0.5)
                                                                                                                                                                                          and ((#s91 <= 0.5)
                                                                                                                                                                                            and ((filesize > 4222.0)
                                                                                                                                                                                              and ((filesize > 4226.0)
                                                                                                                                                                                                and ((filesize <= 5210.0)
                                                                                                                                                                                                  and ((filesize > 5176.0)
                                                                                                                                                                                                  ))))))))))) or (filesize > 12530.0)
                                                                                                                                                                              and ((#s89 <= 3.0)
                                                                                                                                                                                and ((#s109 <= 0.5)
                                                                                                                                                                                  and ((#s110 <= 1.5)
                                                                                                                                                                                    and ((#s86 <= 0.5)
                                                                                                                                                                                      and ((#s91 <= 1.0)
                                                                                                                                                                                        and ((#s113 <= 0.5)
                                                                                                                                                                                          and ((filesize <= 12546.0)
                                                                                                                                                                                          )))) or (#s110 > 1.5)
                                                                                                                                                                                  )))))))))))))))))))))))))) or (filesize > 16468.0)
                                                                                                                                and ((#s145 <= 2.0)
                                                                                                                                  and ((#s146 <= 0.5)
                                                                                                                                    and ((#s147 <= 0.5)
                                                                                                                                      and ((#s148 <= 0.5)
                                                                                                                                        and ((#s149 <= 0.5)
                                                                                                                                          and ((#s72 <= 0.5)
                                                                                                                                            and ((#s151 <= 0.5)
                                                                                                                                              and ((#s71 <= 0.5)
                                                                                                                                                and ((#s83 <= 0.5)
                                                                                                                                                  and ((#s154 <= 0.5)
                                                                                                                                                    and ((#s67 <= 0.5)
                                                                                                                                                      and ((#s156 <= 1.0)
                                                                                                                                                        and ((#s157 <= 0.5)
                                                                                                                                                          and ((#s79 <= 0.5)
                                                                                                                                                            and ((filesize <= 16478.0)
                                                                                                                                                              or (filesize > 16478.0)
                                                                                                                                                              and ((#s88 <= 1.5)
                                                                                                                                                                and ((#s162 <= 0.5)
                                                                                                                                                                  and ((#s163 <= 0.5)
                                                                                                                                                                    and ((#s164 <= 0.5)
                                                                                                                                                                      and ((#s113 <= 0.5)
                                                                                                                                                                        and ((#s166 <= 0.5)
                                                                                                                                                                          and ((#s63 <= 0.5)
                                                                                                                                                                            and ((#s168 <= 1.5)
                                                                                                                                                                              and ((#s169 <= 0.5)
                                                                                                                                                                                and ((#s170 <= 0.5)
                                                                                                                                                                                  and ((#s171 <= 0.5)
                                                                                                                                                                                    and ((#s110 <= 3.0)
                                                                                                                                                                                      and ((#s76 <= 0.5)
                                                                                                                                                                                        and ((#s174 <= 0.5)
                                                                                                                                                                                          and ((#s175 <= 1.0)
                                                                                                                                                                                            and ((#s176 <= 0.5)
                                                                                                                                                                                              and ((#s177 <= 0.5)
                                                                                                                                                                                                and ((#s82 <= 1.0)
                                                                                                                                                                                                  and ((#s81 <= 0.5)
                                                                                                                                                                                                    and ((#s88 <= 0.5)
                                                                                                                                                                                                      and ((#s181 <= 0.5)
                                                                                                                                                                                                        and ((#s182 <= 0.5)
                                                                                                                                                                                                          and ((#s183 <= 0.5)
                                                                                                                                                                                                            and ((#s184 <= 1.0)
                                                                                                                                                                                                              and ((#s64 <= 0.5)
                                                                                                                                                                                                                and ((#s186 <= 0.5)
                                                                                                                                                                                                                  and ((#s187 <= 0.5)
                                                                                                                                                                                                                    and ((#s188 <= 1.5)
                                                                                                                                                                                                                      and ((#s189 <= 0.5)
                                                                                                                                                                                                                        and ((#s190 <= 0.5)
                                                                                                                                                                                                                          and ((#s191 <= 1.0)
                                                                                                                                                                                                                            and ((#s192 <= 0.5)
                                                                                                                                                                                                                              and ((#s193 <= 0.5)
                                                                                                                                                                                                                                and ((#s194 <= 0.5)
                                                                                                                                                                                                                                  and ((#s86 <= 0.5)
                                                                                                                                                                                                                                    and ((#s109 <= 0.5)
                                                                                                                                                                                                                                      and ((#s78 <= 0.5)
                                                                                                                                                                                                                                        and ((#s198 <= 0.5)
                                                                                                                                                                                                                                          and ((#s199 <= 0.5)
                                                                                                                                                                                                                                            and ((#s91 <= 1.0)
                                                                                                                                                                                                                                              and ((#s201 <= 0.5)
                                                                                                                                                                                                                                                and ((#s89 <= 0.5)
                                                                                                                                                                                                                                                  and ((#s75 <= 1.0)
                                                                                                                                                                                                                                                    and ((#s204 <= 1.0)
                                                                                                                                                                                                                                                      and ((#s87 <= 0.5)
                                                                                                                                                                                                                                                        and ((#s206 <= 0.5)
                                                                                                                                                                                                                                                          and ((filesize <= 26130.0)
                                                                                                                                                                                                                                                            and ((#s62 <= 1.0)
                                                                                                                                                                                                                                                              and ((#s209 <= 1.0)
                                                                                                                                                                                                                                                                and ((#s210 <= 0.5)
                                                                                                                                                                                                                                                                  and ((filesize <= 25978.0)
                                                                                                                                                                                                                                                                    and ((#s212 <= 1.0)
                                                                                                                                                                                                                                                                      and ((filesize <= 25072.0)
                                                                                                                                                                                                                                                                        and ((filesize <= 20712.0)
                                                                                                                                                                                                                                                                          and ((filesize > 18966.0)
                                                                                                                                                                                                                                                                            and ((filesize <= 19022.0)
                                                                                                                                                                                                                                                                            )) or (filesize > 20712.0)
                                                                                                                                                                                                                                                                          and ((filesize <= 20802.0)
                                                                                                                                                                                                                                                                            or (filesize > 20802.0)
                                                                                                                                                                                                                                                                            and ((filesize <= 21676.0)
                                                                                                                                                                                                                                                                              and ((filesize <= 21624.0)
                                                                                                                                                                                                                                                                                and ((filesize <= 21100.0)
                                                                                                                                                                                                                                                                                  and ((filesize > 21044.0)
                                                                                                                                                                                                                                                                                  )) or (filesize > 21624.0)
                                                                                                                                                                                                                                                                              )))) or (filesize > 25072.0)
                                                                                                                                                                                                                                                                        and ((filesize <= 25220.0)
                                                                                                                                                                                                                                                                          and ((filesize <= 25136.0)
                                                                                                                                                                                                                                                                            and ((filesize <= 25112.0)
                                                                                                                                                                                                                                                                            ) or (filesize > 25136.0)
                                                                                                                                                                                                                                                                          )))) or (filesize > 25978.0)
                                                                                                                                                                                                                                                                  )))) or (filesize > 26130.0)
                                                                                                                                                                                                                                                            and ((#s62 <= 1.0)
                                                                                                                                                                                                                                                              and ((#s209 <= 1.0)
                                                                                                                                                                                                                                                                and ((filesize > 32962.0)
                                                                                                                                                                                                                                                                  and ((filesize <= 33044.0)
                                                                                                                                                                                                                                                                    or (filesize > 33044.0)
                                                                                                                                                                                                                                                                    and ((filesize <= 38448.0)
                                                                                                                                                                                                                                                                      and ((filesize > 38276.0)
                                                                                                                                                                                                                                                                      ))))))))))))) or (#s91 > 1.0)
                                                                                                                                                                                                                                              and ((#s62 <= 1.0)
                                                                                                                                                                                                                                                and ((filesize <= 19950.5)
                                                                                                                                                                                                                                                )))))))) or (#s194 > 0.5)
                                                                                                                                                                                                                                )))))))))))))))))))))) or (#s110 > 3.0)
                                                                                                                                                                                    ))) or (#s169 > 0.5)
                                                                                                                                                                                and ((#s297 <= 0.5)
                                                                                                                                                                                  and ((#s298 <= 0.5)
                                                                                                                                                                                    and ((#s299 <= 0.5)
                                                                                                                                                                                      and ((#s78 <= 7.5)
                                                                                                                                                                                        and ((#s81 > 1.0)
                                                                                                                                                                                        ))))))))))))) or (#s88 > 1.5)
                                                                                                                                                                and ((#s315 <= 0.5)
                                                                                                                                                                  and ((filesize <= 41198.0)
                                                                                                                                                                    and ((#s193 <= 1.0)
                                                                                                                                                                      and ((#s66 > 0.5)
                                                                                                                                                                      ))))))))))))) or (#s151 > 0.5)
                                                                                                                                            )))) or (#s147 > 0.5)
                                                                                                                                      and ((#s81 <= 1.0)
                                                                                                                                        and ((filesize <= 28162.0)
                                                                                                                                        ))) or (#s146 > 0.5)
                                                                                                                                  )))) or (#s59 > 1.5)
                                                                                                                            and ((#s82 <= 1.5)
                                                                                                                              and ((#s71 > 0.5)
                                                                                                                              ) or (#s82 > 1.5)
                                                                                                                              and ((filesize <= 26556.0)
                                                                                                                                and ((#s12 <= 0.5)
                                                                                                                                ))))) or (#s57 > 0.5)
                                                                                                                      ))) or (#s54 > 0.5)
                                                                                                                )) or (#s52 > 0.5)
                                                                                                              and ((#s358 <= 0.5)
                                                                                                                and ((#s359 > 0.5)
                                                                                                                ))) or (#s51 > 0.5)
                                                                                                          ))) or (#s48 > 0.5)
                                                                                                      and ((#s113 > 0.5)
                                                                                                        and ((#s368 <= 0.5)
                                                                                                          and ((#s369 <= 0.5)
                                                                                                            and ((#s370 > 1.0)
                                                                                                              and ((#s372 <= 0.5)
                                                                                                              )))))) or (#s47 > 0.5)
                                                                                                    and ((#s377 <= 0.5)
                                                                                                      and ((#s192 <= 1.5)
                                                                                                        and ((#s379 <= 0.5)
                                                                                                          and ((#s174 <= 1.0)
                                                                                                            and ((#s381 <= 0.5)
                                                                                                              and ((#s382 <= 1.0)
                                                                                                                and ((#s383 <= 0.5)
                                                                                                                  and ((#s359 <= 0.5)
                                                                                                                    and ((#s385 <= 1.0)
                                                                                                                      and ((#s156 <= 1.5)
                                                                                                                        and ((#s164 <= 1.0)
                                                                                                                          and ((#s64 <= 0.5)
                                                                                                                            and ((#s193 <= 0.5)
                                                                                                                              and ((#s390 <= 1.0)
                                                                                                                                and ((#s50 <= 0.5)
                                                                                                                                  and ((#s62 <= 1.0)
                                                                                                                                    and ((#s56 <= 1.0)
                                                                                                                                      and ((#s394 <= 0.5)
                                                                                                                                        and ((#s395 <= 0.5)
                                                                                                                                          and ((#s171 <= 0.5)
                                                                                                                                            and ((#s52 <= 0.5)
                                                                                                                                              and ((#s398 <= 0.5)
                                                                                                                                                and ((#s81 <= 1.0)
                                                                                                                                                  and ((#s400 <= 0.5)
                                                                                                                                                    and ((#s63 <= 1.5)
                                                                                                                                                      and ((filesize <= 16816.0)
                                                                                                                                                        and ((filesize > 14976.0)
                                                                                                                                                        )) or (#s63 > 1.5)
                                                                                                                                                      and ((#s315 <= 0.5)
                                                                                                                                                        and ((#s408 <= 2.0)
                                                                                                                                                          and ((#s86 <= 1.0)
                                                                                                                                                            and ((#s206 <= 0.5)
                                                                                                                                                              and ((#s47 <= 1.5)
                                                                                                                                                                and ((#s91 <= 1.0)
                                                                                                                                                                  and ((#s74 <= 0.5)
                                                                                                                                                                    and ((#s71 <= 0.5)
                                                                                                                                                                      and ((#s415 <= 0.5)
                                                                                                                                                                        and ((#s416 <= 0.5)
                                                                                                                                                                          and ((#s163 <= 0.5)
                                                                                                                                                                            and ((#s88 <= 1.0)
                                                                                                                                                                              and ((filesize > 36616.0)
                                                                                                                                                                                and ((filesize <= 36800.0)
                                                                                                                                                                                )))))))))))) or (#s408 > 2.0)
                                                                                                                                                        )))) or (#s81 > 1.0)
                                                                                                                                                  and ((filesize <= 29928.0)
                                                                                                                                                  )))))) or (#s394 > 0.5)
                                                                                                                                      ))))))) or (#s164 > 1.0)
                                                                                                                          and ((filesize <= 19048.0)
                                                                                                                          )) or (#s156 > 1.5)
                                                                                                                        and ((#s182 > 0.5)
                                                                                                                          and ((#s64 > 1.5)
                                                                                                                            and ((#s149 <= 0.5)
                                                                                                                            ))))) or (#s359 > 0.5)
                                                                                                                  ) or (#s383 > 0.5)
                                                                                                                  and ((#s299 > 0.5)
                                                                                                                  )) or (#s382 > 1.0)
                                                                                                              ) or (#s381 > 0.5)
                                                                                                            ) or (#s174 > 1.0)
                                                                                                            and ((#s56 <= 1.5)
                                                                                                              and ((#s469 <= 0.5)
                                                                                                                and ((#s470 <= 0.5)
                                                                                                                  and ((#s78 <= 1.0)
                                                                                                                    and ((#s163 > 0.5)
                                                                                                                    )))) or (#s56 > 1.5)
                                                                                                              and ((#s162 <= 0.5)
                                                                                                              ))) or (#s379 > 0.5)
                                                                                                        )) or (#s377 > 0.5)
                                                                                                    )) or (#s46 > 0.5)
                                                                                                ) or (#s45 > 0.5)
                                                                                              )) or (#s43 > 0.5)
                                                                                          ) or (#s42 > 0.5)
                                                                                        ) or (filesize > 49998.0)
                                                                                        and ((#s489 <= 0.5)
                                                                                          and ((#s490 <= 1.5)
                                                                                            and ((#s91 <= 0.5)
                                                                                              and ((#s71 <= 0.5)
                                                                                                and ((#s377 <= 0.5)
                                                                                                  and ((#s169 <= 0.5)
                                                                                                    and ((#s166 <= 0.5)
                                                                                                      and ((#s496 <= 0.5)
                                                                                                        and ((#s497 <= 0.5)
                                                                                                          and ((#s470 <= 0.5)
                                                                                                            and ((#s499 <= 0.5)
                                                                                                              and ((#s500 <= 0.5)
                                                                                                                and ((#s501 <= 0.5)
                                                                                                                  and ((#s66 <= 0.5)
                                                                                                                    and ((#s72 <= 0.5)
                                                                                                                      and ((#s86 <= 0.5)
                                                                                                                        and ((#s163 <= 0.5)
                                                                                                                          and ((#s506 <= 0.5)
                                                                                                                            and ((#s507 <= 0.5)
                                                                                                                              and ((#s182 <= 0.5)
                                                                                                                                and ((#s509 <= 0.5)
                                                                                                                                  and ((#s510 <= 1.0)
                                                                                                                                    and ((#s81 <= 0.5)
                                                                                                                                      and ((filesize <= 50238.0)
                                                                                                                                        and ((#s513 <= 0.5)
                                                                                                                                          and ((#s88 <= 1.0)
                                                                                                                                            and ((#s49 <= 1.5)
                                                                                                                                              and ((filesize <= 50174.5)
                                                                                                                                                and ((filesize <= 50114.0)
                                                                                                                                                  and ((filesize <= 50062.0)
                                                                                                                                                  ) or (filesize > 50114.0)
                                                                                                                                                ) or (filesize > 50174.5)
                                                                                                                                                and ((filesize > 50178.5)
                                                                                                                                                )))) or (#s513 > 0.5)
                                                                                                                                        ) or (filesize > 50238.0)
                                                                                                                                        and ((#s192 <= 1.5)
                                                                                                                                          and ((#s47 <= 0.5)
                                                                                                                                            and ((#s530 <= 0.5)
                                                                                                                                              and ((#s531 <= 0.5)
                                                                                                                                                and ((#s199 <= 1.5)
                                                                                                                                                  and ((#s48 <= 1.5)
                                                                                                                                                    and ((#s156 <= 0.5)
                                                                                                                                                      and ((#s90 <= 0.5)
                                                                                                                                                        and ((#s187 <= 0.5)
                                                                                                                                                          and ((#s85 <= 1.0)
                                                                                                                                                            and ((#s78 <= 0.5)
                                                                                                                                                              and ((#s171 <= 0.5)
                                                                                                                                                                and ((#s540 <= 0.5)
                                                                                                                                                                  and ((#s541 <= 0.5)
                                                                                                                                                                    and ((#s191 <= 0.5)
                                                                                                                                                                      and ((#s398 <= 0.5)
                                                                                                                                                                        and ((#s147 <= 0.5)
                                                                                                                                                                          and ((#s198 <= 0.5)
                                                                                                                                                                            and ((#s177 <= 0.5)
                                                                                                                                                                              and ((#s175 <= 1.0)
                                                                                                                                                                                and ((#s168 <= 0.5)
                                                                                                                                                                                  and ((#s549 <= 1.0)
                                                                                                                                                                                    and ((#s550 <= 0.5)
                                                                                                                                                                                      and ((filesize <= 457204.0)
                                                                                                                                                                                        and ((#s73 <= 0.5)
                                                                                                                                                                                          and ((#s553 <= 0.5)
                                                                                                                                                                                            and ((#s76 <= 0.5)
                                                                                                                                                                                              and ((#s64 <= 0.5)
                                                                                                                                                                                                and ((#s556 <= 0.5)
                                                                                                                                                                                                  and ((#s49 <= 1.0)
                                                                                                                                                                                                    and ((#s201 <= 0.5)
                                                                                                                                                                                                      and ((#s199 <= 0.5)
                                                                                                                                                                                                        and ((#s209 <= 0.5)
                                                                                                                                                                                                          and ((#s561 <= 0.5)
                                                                                                                                                                                                            and ((#s186 <= 0.5)
                                                                                                                                                                                                              and ((#s113 <= 0.5)
                                                                                                                                                                                                                and ((#s564 <= 1.0)
                                                                                                                                                                                                                  and ((#s565 <= 0.5)
                                                                                                                                                                                                                    and ((#s174 <= 0.5)
                                                                                                                                                                                                                      and ((#s63 <= 0.5)
                                                                                                                                                                                                                        and ((#s299 <= 0.5)
                                                                                                                                                                                                                          and ((#s183 <= 0.5)
                                                                                                                                                                                                                            and ((#s74 <= 0.5)
                                                                                                                                                                                                                              and ((#s571 <= 0.5)
                                                                                                                                                                                                                                and ((#s390 <= 1.0)
                                                                                                                                                                                                                                  and ((#s189 <= 0.5)
                                                                                                                                                                                                                                    and ((#s75 <= 1.0)
                                                                                                                                                                                                                                      and ((#s575 <= 0.5)
                                                                                                                                                                                                                                        and ((#s576 <= 0.5)
                                                                                                                                                                                                                                          and ((#s577 <= 0.5)
                                                                                                                                                                                                                                            and ((#s88 <= 0.5)
                                                                                                                                                                                                                                              and ((#s579 <= 0.5)
                                                                                                                                                                                                                                                and ((filesize <= 172899.0)
                                                                                                                                                                                                                                                  and ((#s206 <= 0.5)
                                                                                                                                                                                                                                                    and ((#s582 <= 0.5)
                                                                                                                                                                                                                                                      and ((#s87 <= 0.5)
                                                                                                                                                                                                                                                        and ((filesize <= 99602.0)
                                                                                                                                                                                                                                                          and ((#s585 <= 1.0)
                                                                                                                                                                                                                                                            and ((#s43 <= 0.5)
                                                                                                                                                                                                                                                              and ((filesize <= 99224.0)
                                                                                                                                                                                                                                                                and ((#s79 <= 0.5)
                                                                                                                                                                                                                                                                  and ((#s589 <= 0.5)
                                                                                                                                                                                                                                                                    and ((filesize > 71036.0)
                                                                                                                                                                                                                                                                      and ((filesize <= 71184.0)
                                                                                                                                                                                                                                                                        or (filesize > 71184.0)
                                                                                                                                                                                                                                                                        and ((filesize <= 71394.0)
                                                                                                                                                                                                                                                                          and ((filesize > 71222.0)
                                                                                                                                                                                                                                                                          ) or (filesize > 71394.0)
                                                                                                                                                                                                                                                                          and ((filesize <= 79752.0)
                                                                                                                                                                                                                                                                            and ((filesize > 79704.0)
                                                                                                                                                                                                                                                                            ))))))) or (filesize > 99224.0)
                                                                                                                                                                                                                                                              ))))))) or (filesize > 172899.0)
                                                                                                                                                                                                                                                  and ((#s612 <= 0.5)
                                                                                                                                                                                                                                                    and ((#s154 <= 0.5)
                                                                                                                                                                                                                                                      and ((#s193 <= 0.5)
                                                                                                                                                                                                                                                        and ((#s89 <= 0.5)
                                                                                                                                                                                                                                                          and ((#s206 <= 0.5)
                                                                                                                                                                                                                                                            and ((filesize <= 173868.0)
                                                                                                                                                                                                                                                              or (filesize > 173868.0)
                                                                                                                                                                                                                                                              and ((filesize > 409912.0)
                                                                                                                                                                                                                                                                and ((filesize <= 415252.0)
                                                                                                                                                                                                                                                                ))))))))))))))))))))))))))))))))))))) or (filesize > 457204.0)
                                                                                                                                                                                        and ((#s49 <= 1.0)
                                                                                                                                                                                          and ((#s75 <= 4.0)
                                                                                                                                                                                            and ((#s385 <= 0.5)
                                                                                                                                                                                              and ((#s77 <= 0.5)
                                                                                                                                                                                                and ((#s661 <= 0.5)
                                                                                                                                                                                                  and ((#s662 <= 0.5)
                                                                                                                                                                                                    and ((#s199 <= 0.5)
                                                                                                                                                                                                      and ((#s571 <= 1.0)
                                                                                                                                                                                                        and ((#s665 <= 0.5)
                                                                                                                                                                                                          and ((#s63 <= 0.5)
                                                                                                                                                                                                            and ((#s183 <= 0.5)
                                                                                                                                                                                                              and ((#s668 <= 0.5)
                                                                                                                                                                                                                and ((#s186 <= 0.5)
                                                                                                                                                                                                                  and ((#s612 <= 0.5)
                                                                                                                                                                                                                    and ((#s671 <= 0.5)
                                                                                                                                                                                                                      and ((#s89 <= 44.0)
                                                                                                                                                                                                                        and ((#s67 <= 1.5)
                                                                                                                                                                                                                          and ((#s674 <= 0.5)
                                                                                                                                                                                                                            and ((#s209 <= 1.5)
                                                                                                                                                                                                                              and ((#s206 <= 0.5)
                                                                                                                                                                                                                                and ((#s74 <= 0.5)
                                                                                                                                                                                                                                  and ((#s678 <= 0.5)
                                                                                                                                                                                                                                    and ((filesize <= 467548.0)
                                                                                                                                                                                                                                      and ((filesize <= 462014.0)
                                                                                                                                                                                                                                        or (filesize > 462014.0)
                                                                                                                                                                                                                                        and ((filesize > 465502.0)
                                                                                                                                                                                                                                        )) or (filesize > 467548.0)
                                                                                                                                                                                                                                      and ((filesize <= 628594.0)
                                                                                                                                                                                                                                        and ((filesize > 615196.0)
                                                                                                                                                                                                                                        ) or (filesize > 628594.0)
                                                                                                                                                                                                                                        and ((#s189 <= 0.5)
                                                                                                                                                                                                                                          and ((filesize > 1677491.5)
                                                                                                                                                                                                                                            and ((filesize <= 1780485.5)
                                                                                                                                                                                                                                            )))))))))))))))))))))))))))))))))) or (#s147 > 0.5)
                                                                                                                                                                          and ((filesize > 538887.0)
                                                                                                                                                                          ))))))) or (#s78 > 0.5)
                                                                                                                                                              and ((#s192 > 0.5)
                                                                                                                                                              )))))) or (#s48 > 1.5)
                                                                                                                                                    and ((#s315 <= 1.0)
                                                                                                                                                      and ((#s48 <= 2.5)
                                                                                                                                                      ))) or (#s199 > 1.5)
                                                                                                                                                  and ((#s744 <= 0.5)
                                                                                                                                                    and ((#s575 <= 21.0)
                                                                                                                                                    ))))) or (#s47 > 0.5)
                                                                                                                                            and ((#s50 <= 0.5)
                                                                                                                                              and ((#s752 <= 2.0)
                                                                                                                                                and ((#s174 <= 1.0)
                                                                                                                                                  and ((#s299 <= 0.5)
                                                                                                                                                    and ((#s186 <= 0.5)
                                                                                                                                                      and ((#s147 <= 0.5)
                                                                                                                                                        and ((#s398 <= 0.5)
                                                                                                                                                          and ((#s74 > 0.5)
                                                                                                                                                            and ((#s760 <= 1.0)
                                                                                                                                                              and ((#s761 <= 1.0)
                                                                                                                                                                and ((#s762 <= 1.0)
                                                                                                                                                                  and ((#s678 <= 0.5)
                                                                                                                                                                    and ((filesize <= 366888.0)
                                                                                                                                                                      and ((#s198 > 0.5)
                                                                                                                                                                      ))))))))))))))))) or (#s81 > 0.5)
                                                                                                                                      and ((#s168 <= 1.0)
                                                                                                                                        and ((#s154 <= 0.5)
                                                                                                                                          and ((#s76 <= 1.5)
                                                                                                                                            and ((#s89 <= 10.0)
                                                                                                                                              and ((#s785 <= 0.5)
                                                                                                                                                and ((#s561 <= 0.5)
                                                                                                                                                  and ((#s571 <= 1.0)
                                                                                                                                                    and ((#s77 <= 0.5)
                                                                                                                                                      and ((#s190 <= 0.5)
                                                                                                                                                        and ((#s81 > 1.5)
                                                                                                                                                          and ((#s792 <= 2.0)
                                                                                                                                                            and ((#s793 <= 1.0)
                                                                                                                                                              and ((#s85 <= 1.0)
                                                                                                                                                                and ((#s415 <= 0.5)
                                                                                                                                                                  and ((#s198 <= 0.5)
                                                                                                                                                                    and ((#s186 <= 0.5)
                                                                                                                                                                      and ((#s74 <= 0.5)
                                                                                                                                                                        and ((#s395 <= 0.5)
                                                                                                                                                                          and ((#s678 <= 0.5)
                                                                                                                                                                            and ((#s209 <= 0.5)
                                                                                                                                                                              and ((#s802 <= 1.0)
                                                                                                                                                                                and ((#s48 <= 0.5)
                                                                                                                                                                                  and ((filesize > 287642.0)
                                                                                                                                                                                    and ((#s582 <= 0.5)
                                                                                                                                                                                      and ((#s807 <= 1.0)
                                                                                                                                                                                        and ((#s177 <= 0.5)
                                                                                                                                                                                          and ((#s64 <= 1.0)
                                                                                                                                                                                            and ((#s47 <= 0.5)
                                                                                                                                                                                              and ((#s201 <= 0.5)
                                                                                                                                                                                                and ((#s812 <= 0.5)
                                                                                                                                                                                                  and ((#s50 <= 0.5)
                                                                                                                                                                                                    and ((#s81 <= 3.0)
                                                                                                                                                                                                      and ((filesize <= 309258.0)
                                                                                                                                                                                                      )))))))))))))))))))))))))))))) or (#s76 > 1.5)
                                                                                                                                            and ((#s81 <= 3.0)
                                                                                                                                              and ((#s76 <= 2.5)
                                                                                                                                                and ((#s847 <= 0.5)
                                                                                                                                                ))))) or (#s168 > 1.0)
                                                                                                                                      ))) or (#s509 > 0.5)
                                                                                                                                ) or (#s182 > 0.5)
                                                                                                                                and ((#s154 > 0.5)
                                                                                                                                  and ((#s210 <= 0.5)
                                                                                                                                    and ((#s75 <= 1.0)
                                                                                                                                      and ((#s156 <= 1.5)
                                                                                                                                        and ((#s416 > 0.5)
                                                                                                                                        )))))))) or (#s163 > 0.5)
                                                                                                                          and ((filesize <= 69888.0)
                                                                                                                            and ((#s206 <= 0.5)
                                                                                                                              and ((#s415 <= 0.5)
                                                                                                                                and ((#s88 <= 1.0)
                                                                                                                                  and ((#s395 <= 0.5)
                                                                                                                                    and ((filesize > 68889.0)
                                                                                                                                    ) or (#s395 > 0.5)
                                                                                                                                  )))))))) or (#s66 > 0.5)
                                                                                                                    and ((#s612 <= 0.5)
                                                                                                                      and ((#s507 <= 0.5)
                                                                                                                        and ((#s47 <= 0.5)
                                                                                                                          and ((#s887 <= 1.0)
                                                                                                                            and ((#s154 <= 0.5)
                                                                                                                              and ((#s145 <= 2.0)
                                                                                                                                and ((#s193 <= 1.0)
                                                                                                                                  and ((filesize > 9388564.0)
                                                                                                                                    and ((#s78 <= 1.0)
                                                                                                                                      and ((#s198 <= 0.5)
                                                                                                                                        and ((#s66 <= 1.5)
                                                                                                                                          and ((filesize <= 10658932.0)
                                                                                                                                          ))))))) or (#s154 > 0.5)
                                                                                                                              and ((#s17 <= 0.5)
                                                                                                                                and ((#s63 <= 1.0)
                                                                                                                                  and ((#s81 <= 0.5)
                                                                                                                                    and ((#s77 > 0.5)
                                                                                                                                      and ((#s78 <= 1.0)
                                                                                                                                        and ((filesize > 9065528.0)
                                                                                                                                          and ((#s912 > 1.0)
                                                                                                                                          )))))))))) or (#s507 > 0.5)
                                                                                                                        and ((#s47 <= 0.5)
                                                                                                                          and ((#s78 <= 18.0)
                                                                                                                          ))))) or (#s501 > 0.5)
                                                                                                                ) or (#s500 > 0.5)
                                                                                                              ) or (#s499 > 0.5)
                                                                                                            ) or (#s470 > 0.5)
                                                                                                            and ((#s507 <= 0.5)
                                                                                                              and ((#s931 <= 0.5)
                                                                                                                and ((#s932 <= 1.0)
                                                                                                                  and ((#s50 <= 1.5)
                                                                                                                    and ((#s176 > 0.5)
                                                                                                                      and ((#s77 > 0.5)
                                                                                                                        and ((#s938 <= 1.0)
                                                                                                                          and ((#s549 <= 1.0)
                                                                                                                          )))) or (#s50 > 1.5)
                                                                                                                  ))))) or (#s497 > 0.5)
                                                                                                        )) or (#s166 > 0.5)
                                                                                                      and ((#s949 <= 0.5)
                                                                                                        and ((#s950 <= 0.5)
                                                                                                          and ((#s951 <= 1.5)
                                                                                                            and ((#s77 <= 1.0)
                                                                                                              and ((#s398 <= 0.5)
                                                                                                                and ((#s954 <= 3.0)
                                                                                                                  and ((#s955 <= 1.0)
                                                                                                                    and ((#s571 <= 1.0)
                                                                                                                      and ((#s163 <= 0.5)
                                                                                                                        and ((#s81 <= 1.0)
                                                                                                                          and ((filesize <= 321685.5)
                                                                                                                            and ((#s63 > 1.5)
                                                                                                                              and ((filesize > 244685.5)
                                                                                                                              )))))))))) or (#s951 > 1.5)
                                                                                                          ) or (#s950 > 0.5)
                                                                                                          and ((#s89 <= 167.5)
                                                                                                          )) or (#s949 > 0.5)
                                                                                                      ))) or (#s377 > 0.5)
                                                                                                )) or (#s91 > 0.5)
                                                                                              and ((#s210 <= 0.5)
                                                                                                and ((#s56 <= 0.5)
                                                                                                  and ((#s983 <= 0.5)
                                                                                                    and ((#s74 <= 0.5)
                                                                                                      and ((#s985 <= 0.5)
                                                                                                        and ((#s59 <= 1.5)
                                                                                                          and ((#s556 <= 0.5)
                                                                                                            and ((#s166 <= 0.5)
                                                                                                              and ((#s77 <= 0.5)
                                                                                                                and ((#s186 <= 0.5)
                                                                                                                  and ((#s169 <= 0.5)
                                                                                                                    and ((#s992 <= 1.0)
                                                                                                                      and ((#s993 <= 0.5)
                                                                                                                        and ((#s78 <= 2.5)
                                                                                                                          and ((#s75 <= 1.0)
                                                                                                                            and ((#s390 <= 1.0)
                                                                                                                              and ((#s162 <= 0.5)
                                                                                                                                and ((#s496 <= 1.0)
                                                                                                                                  and ((#s88 <= 0.5)
                                                                                                                                    and ((#s72 <= 0.5)
                                                                                                                                      and ((#s66 <= 0.5)
                                                                                                                                        and ((#s187 <= 0.5)
                                                                                                                                          and ((#s192 <= 0.5)
                                                                                                                                            and ((#s79 <= 0.5)
                                                                                                                                              and ((#s147 <= 4.5)
                                                                                                                                                and ((#s198 <= 0.5)
                                                                                                                                                  and ((#s62 <= 1.0)
                                                                                                                                                    and ((#s762 <= 1.0)
                                                                                                                                                      and ((#s1009 <= 0.5)
                                                                                                                                                        and ((#s78 <= 1.0)
                                                                                                                                                          and ((#s63 <= 0.5)
                                                                                                                                                            and ((filesize > 601000.0)
                                                                                                                                                              and ((#s71 <= 0.5)
                                                                                                                                                                and ((filesize <= 612436.0)
                                                                                                                                                                ))))))))))))))))) or (#s162 > 0.5)
                                                                                                                              ))))))))))) or (#s59 > 1.5)
                                                                                                          and ((#s556 <= 0.5)
                                                                                                            and ((#s315 <= 0.5)
                                                                                                              and ((#s82 > 1.0)
                                                                                                                and ((#s1048 <= 1.5)
                                                                                                                  and ((#s1048 <= 0.5)
                                                                                                                    and ((filesize > 1187814.0)
                                                                                                                    ) or (#s1048 > 0.5)
                                                                                                                    and ((filesize <= 1136760.0)
                                                                                                                      and ((#s1056 <= 0.5)
                                                                                                                      ) or (filesize > 1136760.0)
                                                                                                                      and ((#s1056 <= 0.5)
                                                                                                                        and ((filesize <= 7578068.0)
                                                                                                                        )))) or (#s1048 > 1.5)
                                                                                                                ))))) or (#s985 > 0.5)
                                                                                                      )) or (#s983 > 0.5)
                                                                                                  )) or (#s210 > 0.5)
                                                                                                and ((#s1071 <= 0.5)
                                                                                                  and ((#s1072 > 0.5)
                                                                                                  ) or (#s1071 > 0.5)
                                                                                                  and ((#s162 <= 0.5)
                                                                                                    and ((#s385 <= 1.0)
                                                                                                      and ((#s81 <= 0.5)
                                                                                                      ) or (#s385 > 1.0)
                                                                                                    ))))) or (#s490 > 1.5)
                                                                                          ) or (#s489 > 0.5)
                                                                                        )) or (#s40 > 0.5)
                                                                                      and ((#s1084 <= 0.5)
                                                                                        and ((#s1085 <= 0.5)
                                                                                          and ((#s206 <= 0.5)
                                                                                            and ((#s42 <= 0.5)
                                                                                              and ((#s1088 <= 0.5)
                                                                                                and ((#s1089 <= 0.5)
                                                                                                  and ((#s1090 <= 1.0)
                                                                                                    and ((#s72 <= 0.5)
                                                                                                      and ((#s1092 > 0.5)
                                                                                                      )) or (#s1090 > 1.0)
                                                                                                  ))) or (#s42 > 0.5)
                                                                                              and ((#s589 > 0.5)
                                                                                                and ((#s370 <= 0.5)
                                                                                                ))) or (#s206 > 0.5)
                                                                                            and ((#s73 <= 1.0)
                                                                                              and ((#s1105 > 0.5)
                                                                                                and ((#s297 <= 1.5)
                                                                                                  and ((#s368 <= 0.5)
                                                                                                  ))) or (#s73 > 1.0)
                                                                                              and ((#s385 <= 1.0)
                                                                                                and ((#s1113 <= 0.5)
                                                                                                )))) or (#s1085 > 0.5)
                                                                                        ) or (#s1084 > 0.5)
                                                                                        and ((#s1118 <= 0.5)
                                                                                          and ((#s506 <= 0.5)
                                                                                            and ((#s1120 <= 0.5)
                                                                                              and ((#s113 <= 0.5)
                                                                                                and ((#s56 <= 1.0)
                                                                                                  and ((#s50 <= 0.5)
                                                                                                  ))))) or (#s1118 > 0.5)
                                                                                        ))) or (#s39 > 1.0)
                                                                                  ) or (#s38 > 0.5)
                                                                                ) or (#s37 > 1.0)
                                                                              ) or (#s36 > 1.0)
                                                                            ) or (#s35 > 0.5)
                                                                            and ((#s1135 <= 2.5)
                                                                              and ((#s113 <= 0.5)
                                                                                and ((#s665 <= 0.5)
                                                                                  and ((#s187 <= 0.5)
                                                                                    and ((#s1113 <= 0.5)
                                                                                      and ((#s1140 <= 0.5)
                                                                                        and ((#s556 <= 0.5)
                                                                                          and ((#s1142 <= 0.5)
                                                                                            and ((#s70 <= 0.5)
                                                                                              and ((#s1144 <= 1.0)
                                                                                                and ((#s1145 <= 0.5)
                                                                                                  and ((#s201 <= 0.5)
                                                                                                    and ((#s56 > 1.0)
                                                                                                      and ((#s48 <= 0.5)
                                                                                                        and ((#s395 <= 0.5)
                                                                                                          and ((#s661 <= 1.5)
                                                                                                            and ((#s1152 <= 1.5)
                                                                                                              and ((#s163 <= 0.5)
                                                                                                                and ((#s1154 <= 0.5)
                                                                                                                  and ((#s50 <= 0.5)
                                                                                                                    and ((#s90 <= 1.0)
                                                                                                                      and ((filesize > 76568.0)
                                                                                                                      ))))))))))))))))))) or (#s665 > 0.5)
                                                                                  and ((#s1177 > 1.5)
                                                                                  ))) or (#s1135 > 2.5)
                                                                            )) or (#s34 > 0.5)
                                                                        ) or (#s33 > 0.5)
                                                                      ) or (#s32 > 0.5)
                                                                      and ((#s299 <= 1.0)
                                                                      )) or (#s31 > 0.5)
                                                                  ) or (#s30 > 0.5)
                                                                ) or (#s29 > 0.5)
                                                                and ((#s44 <= 1.0)
                                                                  and ((#s1190 <= 1.5)
                                                                    and ((#s56 > 1.0)
                                                                    )) or (#s44 > 1.0)
                                                                )) or (#s28 > 0.5)
                                                            ) or (#s27 > 0.5)
                                                          ) or (#s26 > 2.0)
                                                        ) or (#s25 > 0.5)
                                                      ) or (#s24 > 0.5)
                                                    ) or (#s23 > 0.5)
                                                  ) or (#s22 > 0.5)
                                                ) or (#s21 > 0.5)
                                              ) or (#s20 > 0.5)
                                            ) or (#s19 > 0.5)
                                          ) or (#s18 > 0.5)
                                        ) or (#s17 > 1.5)
                                        and ((#s75 <= 1.0)
                                          and ((#s91 <= 0.5)
                                            and ((#s74 <= 1.0)
                                              and ((#s530 <= 0.5)
                                                and ((#s77 <= 1.0)
                                                  and ((#s81 <= 1.0)
                                                    and ((filesize > 25292.0)
                                                    )))))))) or (#s16 > 0.5)
                                    ) or (#s15 > 1.0)
                                    and ((#s182 <= 0.5)
                                      and ((#s470 > 0.5)
                                      ) or (#s182 > 0.5)
                                    )) or (#s14 > 0.5)
                                  and ((#s1228 <= 0.5)
                                    and ((#s1229 <= 0.5)
                                      and ((#s181 <= 0.5)
                                        and ((#s1231 > 0.5)
                                        ) or (#s181 > 0.5)
                                        and ((#s1234 > 1.5)
                                        ))))) or (#s13 > 0.5)
                              ) or (#s12 > 1.5)
                              and ((#s72 <= 1.0)
                                and ((#s1241 <= 0.5)
                                  and ((#s42 <= 3.5)
                                    and ((#s59 > 1.0)
                                      and ((#s82 > 1.0)
                                        and ((filesize > 10528.0)
                                          and ((filesize > 14024.0)
                                          )))))))) or (#s11 > 2.0)
                          ) or (#s10 > 0.5)
                        ) or (#s9 > 0.5)
                      ) or (#s8 > 0.5)
                    ) or (#s7 > 0.5)
                  ) or (#s6 > 0.5)
                ) or (#s5 > 0.5)
                and ((#s955 <= 0.5)
                  and ((#s189 <= 2.5)
                    and ((#s540 > 0.5)
                      and ((#s1267 <= 2.5)
                        and ((#s1268 <= 1.5)
                          or (#s1268 > 1.5)
                          and ((#s1270 <= 4.5)
                            or (#s1270 > 4.5)
                            and ((#s89 > 240.0)
                            ))) or (#s1267 > 2.5)
                      ))))) or (#s4 > 0.5)
            ) or (#s3 > 0.5)
            and ((#s163 <= 0.5)
              and ((#s297 <= 0.5)
                and ((#s1281 <= 1.0)
                  and ((#s1282 <= 2.5)
                    and ((#s182 <= 0.5)
                      and ((#s1284 <= 0.5)
                        and ((#s1285 <= 0.5)
                          and ((#s1286 <= 1.0)
                            and ((#s1287 <= 1.0)
                              and ((#s793 <= 1.0)
                                and ((#s1289 <= 1.0)
                                  and ((#s70 <= 2.5)
                                    and ((#s1291 <= 1.5)
                                      and ((#s1292 <= 7.5)
                                        and ((#s1293 <= 0.5)
                                          and ((#s1294 <= 5.5)
                                            and ((#s1295 <= 0.5)
                                              and ((#s50 <= 1.5)
                                                and ((#s78 <= 1.0)
                                                  and ((#s72 <= 1.5)
                                                    and ((#s201 > 1.5)
                                                      and ((#s64 > 1.0)
                                                        and ((#s1303 <= 1.5)
                                                          and ((#s154 <= 1.0)
                                                            and ((#s1305 > 0.5)
                                                              and ((#s1307 > 0.5)
                                                              )))))))) or (#s50 > 1.5)
                                              ) or (#s1295 > 0.5)
                                            ) or (#s1294 > 5.5)
                                            and ((#s1316 <= 0.5)
                                              and ((#s1317 <= 1.0)
                                                and ((#s1307 <= 0.5)
                                                  and ((#s1319 > 0.5)
                                                  )) or (#s1317 > 1.0)
                                              ) or (#s1316 > 0.5)
                                            )) or (#s1293 > 0.5)
                                        ) or (#s1292 > 7.5)
                                        and ((#s63 <= 1.0)
                                          or (#s63 > 1.0)
                                          and ((#s358 > 1.0)
                                            and ((filesize <= 232856.0)
                                            )))) or (#s1291 > 1.5)
                                    ) or (#s70 > 2.5)
                                    and ((#s1334 <= 1.0)
                                      and ((#s1335 <= 1.0)
                                        and ((#s1336 <= 1.0)
                                          and ((#s1337 <= 1.0)
                                          )) or (#s1335 > 1.0)
                                      ) or (#s1334 > 1.0)
                                    ))) or (#s793 > 1.0)
                                and ((#s1294 <= 1.5)
                                )) or (#s1287 > 1.0)
                            ) or (#s1286 > 1.0)
                          ) or (#s1285 > 0.5)
                        ) or (#s1284 > 0.5)
                      ) or (#s182 > 0.5)
                      and ((#s170 <= 0.5)
                        and ((#s1352 <= 0.5)
                          and ((#s564 <= 1.0)
                            and ((#s210 <= 0.5)
                              and ((#s1355 > 0.5)
                                and ((#s1336 <= 1.5)
                                  and ((#s469 <= 2.0)
                                    and ((filesize <= 107704.0)
                                    )))) or (#s210 > 0.5)
                              and ((#s1364 > 0.5)
                                and ((#s1366 > 0.5)
                                ))) or (#s564 > 1.0)
                            and ((#s1369 > 1.0)
                              and ((#s1371 <= 0.5)
                                and ((#s368 <= 0.5)
                                )))) or (#s1352 > 0.5)
                        ) or (#s170 > 0.5)
                        and ((#s1294 <= 4.5)
                          and ((#s83 <= 1.5)
                            and ((#s1379 > 1.5)
                            ) or (#s83 > 1.5)
                          ) or (#s1294 > 4.5)
                          and ((filesize > 186600.0)
                          )))) or (#s1282 > 2.5)
                    and ((filesize <= 1602256.5)
                      and ((#s1387 <= 1.0)
                        and ((#s1388 <= 9.0)
                        ) or (#s1387 > 1.0)
                      ))) or (#s1281 > 1.0)
                  and ((#s1145 > 1.0)
                    and ((#s63 <= 1.0)
                    ))) or (#s297 > 0.5)
                and ((#s1398 <= 1.5)
                  and ((#s1364 <= 0.5)
                    and ((#s149 <= 0.5)
                      and ((#s72 <= 1.5)
                        and ((#s1402 <= 1.5)
                          and ((#s170 <= 0.5)
                            and ((#s1404 > 2.0)
                            ) or (#s170 > 0.5)
                            and ((#s1407 <= 1.0)
                              and ((#s793 <= 1.0)
                                and ((#s398 <= 0.5)
                                  and ((#s81 <= 1.5)
                                    or (#s81 > 1.5)
                                    and ((#s1084 <= 0.5)
                                      and ((#s1413 <= 1.5)
                                        and ((#s589 <= 0.5)
                                        ) or (#s1413 > 1.5)
                                      ))))))) or (#s1402 > 1.5)
                        ) or (#s72 > 1.5)
                        and ((#s1423 > 0.5)
                        )) or (#s149 > 0.5)
                      and ((#s1426 <= 0.5)
                        and ((#s1427 <= 0.5)
                          and ((#s1428 <= 1.0)
                            and ((#s72 <= 2.5)
                              and ((#s1071 > 0.5)
                                and ((#s69 > 0.5)
                                  and ((#s372 <= 0.5)
                                  ))) or (#s72 > 2.5)
                              and ((#s1437 <= 0.5)
                                and ((#s1438 <= 0.5)
                                  and ((#s1439 <= 0.5)
                                    and ((#s1440 <= 0.5)
                                      and ((#s69 <= 0.5)
                                        and ((#s1442 > 1.0)
                                          and ((#s1444 <= 4.0)
                                          )))) or (#s1439 > 0.5)
                                  ) or (#s1438 > 0.5)
                                ) or (#s1437 > 0.5)
                                and ((#s63 > 1.0)
                                ))) or (#s1428 > 1.0)
                          )) or (#s1426 > 0.5)
                        and ((#s1456 <= 0.5)
                          and ((#s1457 <= 0.5)
                            or (#s1457 > 0.5)
                            and ((#s156 > 2.0)
                            ))))) or (#s1364 > 0.5)
                    and ((#s1113 <= 2.5)
                      and ((#s1464 <= 0.5)
                        and ((#s932 <= 0.5)
                          and ((#s577 <= 0.5)
                            and ((filesize > 80152.0)
                              and ((#s1456 <= 0.5)
                                and ((#s168 > 0.5)
                                  and ((#s52 <= 0.5)
                                    and ((#s90 <= 2.0)
                                      and ((#s1307 <= 0.5)
                                        and ((#s1475 <= 1.0)
                                          and ((#s1476 <= 0.5)
                                            or (#s1476 > 0.5)
                                            and ((#s1478 > 1.0)
                                            )) or (#s1475 > 1.0)
                                        ) or (#s1307 > 0.5)
                                      )) or (#s52 > 0.5)
                                  )) or (#s1456 > 0.5)
                              )))) or (#s1464 > 0.5)
                        and ((#s174 > 1.0)
                          and ((#s1490 <= 0.5)
                            and ((#s887 > 1.0)
                            ) or (#s1490 > 0.5)
                            and ((#s1494 <= 1.5)
                              and ((#s74 <= 0.5)
                                and ((#s1496 > 0.5)
                                )) or (#s1494 > 1.5)
                              and ((#s1500 <= 6.0)
                              ))))) or (#s1113 > 2.5)
                      and ((#s1503 > 1.5)
                      ))))) or (#s163 > 0.5)
              and ((filesize <= 71496.0)
                and ((#s148 <= 0.5)
                  and ((#s1509 > 1.0)
                  ) or (#s148 > 0.5)
                ) or (filesize > 71496.0)
                and ((#s109 <= 1.0)
                  and ((#s1294 <= 4.5)
                    and ((#s1515 > 0.5)
                    ) or (#s1294 > 4.5)
                    and ((#s802 <= 3.0)
                      and ((#s1229 <= 0.5)
                        and ((#s1113 <= 0.5)
                          and ((#s1305 <= 0.5)
                            and ((#s1522 <= 1.0)
                              and ((#s174 <= 1.0)
                                and ((#s1524 > 0.5)
                                ) or (#s174 > 1.0)
                                and ((#s1527 > 1.0)
                                ))) or (#s1305 > 0.5)
                          )) or (#s1229 > 0.5)
                        and ((#s1533 <= 6.0)
                        )))) or (#s109 > 1.0)
                  and ((#s47 > 0.5)
                    and ((#s1539 <= 0.5)
                      and ((#s1540 <= 1.5)
                        and ((#s1541 > 1.0)
                        ) or (#s1540 > 1.5)
                      ))))))) or (#s2 > 1.0)
          and ((#s35 <= 0.5)
          )) or (#s1 > 0.5)
        and ((#s1177 <= 17.5)
          and ((#s1550 <= 1.0)
            and ((#s1551 <= 0.5)
              and ((#s1552 <= 1.0)
                and ((#s168 <= 1.5)
                  and ((#s1554 <= 0.5)
                    and ((#s53 <= 0.5)
                      and ((#s674 <= 0.5)
                        and ((#s164 > 1.0)
                        )) or (#s53 > 0.5)
                      and ((#s187 <= 1.0)
                        and ((#s1388 <= 1.0)
                          and ((filesize > 9040853.5)
                          ) or (#s1388 > 1.0)
                        ))) or (#s1554 > 0.5)
                    and ((#s1568 <= 0.5)
                    )) or (#s168 > 1.5)
                  and ((#s65 > 1.0)
                    and ((#s1388 <= 9.0)
                      and ((#s83 <= 0.5)
                        and ((#s792 <= 1.0)
                          and ((#s56 <= 3.0)
                            and ((#s81 <= 1.0)
                            )) or (#s792 > 1.0)
                        ) or (#s83 > 0.5)
                        and ((#s1582 > 1.0)
                        )) or (#s1388 > 9.0)
                    ))) or (#s1552 > 1.0)
              ) or (#s1551 > 0.5)
              and ((#s1587 <= 0.5)
                and ((#s1145 <= 1.0)
                  and ((#s1589 <= 0.5)
                    and ((#s1444 <= 0.5)
                      and ((#s1591 <= 0.5)
                        and ((#s75 <= 1.0)
                          and ((#s1593 <= 1.0)
                            and ((#s50 <= 0.5)
                              and ((#s1364 <= 0.5)
                                and ((#s174 <= 1.0)
                                  and ((#s58 <= 0.5)
                                    and ((#s1527 <= 1.0)
                                      and ((#s1599 <= 1.0)
                                        and ((#s665 <= 0.5)
                                          and ((#s63 > 0.5)
                                          ) or (#s665 > 0.5)
                                          and ((#s1604 > 0.5)
                                          )))) or (#s58 > 0.5)
                                    and ((#s1609 <= 1.0)
                                      and ((#s1610 <= 0.5)
                                      )))) or (#s1364 > 0.5)
                                and ((#s1615 <= 0.5)
                                )))) or (#s75 > 1.0)
                          and ((#s1620 <= 2.0)
                            and ((#s1621 <= 1.5)
                              and ((#s56 <= 1.0)
                                and ((#s69 <= 0.5)
                                  and ((#s1456 <= 0.5)
                                  ))) or (#s1621 > 1.5)
                              and ((#s1629 > 1.0)
                                and ((#s1631 > 3.0)
                                ))) or (#s1620 > 2.0)
                          )) or (#s1591 > 0.5)
                      ) or (#s1444 > 0.5)
                      and ((#s1524 <= 0.5)
                        and ((#s190 <= 2.0)
                          and ((#s1444 <= 2.5)
                            or (#s1444 > 2.5)
                            and ((#s372 <= 0.5)
                              and ((#s1364 <= 0.5)
                                and ((#s73 <= 2.0)
                                  and ((#s1527 <= 1.0)
                                    and ((#s50 <= 0.5)
                                    )) or (#s73 > 2.0)
                                  and ((#s1648 <= 0.5)
                                    or (#s1648 > 0.5)
                                    and ((#s1305 <= 0.5)
                                      or (#s1305 > 0.5)
                                      and ((#s470 > 0.5)
                                      )))) or (#s1364 > 0.5)
                              ))) or (#s190 > 2.0)
                          and ((#s370 <= 1.0)
                            and ((#s556 <= 0.5)
                              and ((#s174 <= 1.0)
                                and ((#s1527 <= 1.0)
                                  or (#s1527 > 1.0)
                                  and ((#s1662 <= 0.5)
                                  )))) or (#s370 > 1.0)
                          )) or (#s1524 > 0.5)
                        and ((#s1316 <= 0.5)
                          and ((#s182 > 0.5)
                            and ((#s1620 <= 0.5)
                              and ((#s182 <= 1.5)
                                and ((#s44 <= 1.0)
                                  and ((#s1336 > 1.5)
                                    and ((#s183 <= 1.0)
                                      and ((#s530 <= 0.5)
                                        and ((#s72 <= 2.0)
                                          and ((#s1679 <= 0.5)
                                            and ((#s148 > 0.5)
                                            ) or (#s1679 > 0.5)
                                          )) or (#s530 > 0.5)
                                        and ((#s1478 <= 1.0)
                                        ))))) or (#s182 > 1.5)
                                and ((#s1690 <= 1.0)
                                  and ((#s176 <= 1.5)
                                    and ((#s1692 <= 1.0)
                                      and ((#s3 <= 2.0)
                                        and ((#s1152 <= 0.5)
                                          and ((#s370 > 0.5)
                                          ) or (#s1152 > 0.5)
                                        ) or (#s3 > 2.0)
                                        and ((#s1444 > 4.0)
                                          and ((#s1662 <= 1.5)
                                            and ((#s170 > 0.5)
                                            ) or (#s1662 > 1.5)
                                          ))) or (#s1692 > 1.0)
                                    )) or (#s1690 > 1.0)
                                )) or (#s1620 > 0.5)
                              and ((#s1120 <= 0.5)
                                and ((#s553 > 0.5)
                                  and ((#s530 > 0.5)
                                  )) or (#s1120 > 0.5)
                                and ((#s1715 <= 1.5)
                                )))) or (#s1316 > 0.5)
                        ))) or (#s1589 > 0.5)
                    and ((#s1228 > 0.5)
                    )) or (#s1145 > 1.0)
                  and ((#s887 <= 1.0)
                    and ((#s50 <= 0.5)
                      and ((#s1724 <= 4.0)
                        and ((#s847 <= 0.5)
                          and ((#s190 <= 0.5)
                            and ((#s1727 <= 0.5)
                              and ((#s1728 <= 0.5)
                                and ((#s1729 <= 0.5)
                                  and ((#s752 <= 1.0)
                                    and ((#s182 <= 1.5)
                                      and ((#s1732 > 0.5)
                                      ) or (#s182 > 1.5)
                                    ) or (#s752 > 1.0)
                                  ) or (#s1729 > 0.5)
                                ))) or (#s190 > 0.5)
                            and ((#s1496 <= 0.5)
                              and ((#s52 <= 0.5)
                                and ((#s1554 <= 2.0)
                                  and ((#s47 <= 0.5)
                                    or (#s47 > 0.5)
                                    and ((#s1503 > 0.5)
                                      and ((#s1118 <= 0.5)
                                        and ((#s1748 <= 1.0)
                                          and ((#s501 > 1.0)
                                          )) or (#s1118 > 0.5)
                                        and ((#s1407 <= 1.0)
                                        ))))) or (#s52 > 0.5)
                                and ((#s1337 <= 0.5)
                                  and ((#s71 <= 0.5)
                                  ) or (#s1337 > 0.5)
                                )) or (#s1496 > 0.5)
                            )) or (#s847 > 0.5)
                          and ((#s1763 > 1.0)
                          )) or (#s1724 > 4.0)
                      ) or (#s50 > 0.5)
                      and ((#s182 > 0.5)
                        and ((#s1621 <= 1.5)
                          or (#s1621 > 1.5)
                          and ((#s156 > 3.0)
                            and ((#s1773 > 2.0)
                            ))))))) or (#s1587 > 0.5)
                and ((#s1777 <= 0.5)
                  and ((#s166 > 3.5)
                  )))) or (#s1550 > 1.0)
            and ((#s163 <= 0.5)
              and ((#s1503 <= 0.5)
                and ((#s162 <= 1.0)
                ) or (#s1503 > 0.5)
                and ((#s469 <= 3.0)
                  and ((#s154 <= 4.0)
                  ))) or (#s163 > 0.5)
              and ((filesize <= 211096.0)
              ))) or (#s1177 > 17.5)
          and ((#s668 <= 0.5)
            and ((#s77 <= 1.0)
              and ((#s1457 <= 0.5)
                and ((#s65 <= 1.0)
                  and ((#s1379 <= 2.0)
                    and ((#s1800 > 3.0)
                      and ((#s1802 > 1.5)
                      )) or (#s1379 > 2.0)
                  )) or (#s1457 > 0.5)
                and ((#s1807 > 0.5)
                )) or (#s77 > 1.0)
              and ((#s1478 <= 1.0)
                and ((#s1524 <= 1.5)
                  and ((#s1812 <= 1.0)
                    and ((#s148 <= 0.5)
                      or (#s148 > 0.5)
                      and ((#s1177 > 25.5)
                        and ((#s931 <= 0.5)
                          or (#s931 > 0.5)
                          and ((#s802 <= 1.0)
                            and ((#s1824 <= 0.5)
                              or (#s1824 > 0.5)
                              and ((filesize > 18004136.0)
                              )) or (#s802 > 1.0)
                            and ((#s168 <= 2.5)
                              and ((filesize <= 19809960.0)
                                and ((#s1048 <= 2.5)
                                  and ((#s1056 <= 0.5)
                                  ) or (#s1048 > 2.5)
                                )) or (#s168 > 2.5)
                              and ((#s1837 <= 0.5)
                                and ((#s89 <= 59.0)
                                  and ((filesize <= 11259016.0)
                                  ) or (#s89 > 59.0)
                                )))))))) or (#s1524 > 1.5)
                  and ((filesize <= 25131176.0)
                    and ((#s1846 <= 2.0)
                      and ((#s198 <= 1.5)
                        and ((#s188 > 3.0)
                          and ((#s1850 <= 12.0)
                            and ((filesize <= 17175080.0)
                            ))) or (#s198 > 1.5)
                        and ((#s109 > 2.0)
                        )) or (#s1846 > 2.0)
                      and ((filesize <= 23943144.0)
                        or (filesize > 23943144.0)
                        and ((#s1056 <= 0.5)
                        ))) or (filesize > 25131176.0)
                    and ((#s1444 <= 3.0)
                      or (#s1444 > 3.0)
                      and ((#s1865 > 1.0)
                        and ((#s1837 <= 0.5)
                        ))))))) or (#s668 > 0.5)
            and ((#s1413 <= 1.5)
              and ((#s1872 > 1.0)
                and ((#s73 <= 3.0)
                )) or (#s1413 > 1.5)
              and ((#s1877 > 2.0)
              ))))) or (#s0 > 0.5)
    )
}